#!/usr/bin/env python3
"""
Identify an OPTIGA Trust M shield attached to an RP2040 board and record it
in boards.json.

The OPTIGA Coprocessor UID (OID 0xE0C2) identifies the *shield*; the RP2040
USB serial (its unique flash ID) identifies the *host board*. Both are stored
so a shield can be tracked across host boards and vice versa.

Usage:
    ./identify.py                    # read UID, flashing the probe only if needed
    ./identify.py --no-flash         # never touch the board's flash
    ./identify.py --flash            # always reflash the probe first
    ./identify.py --label "spare"    # attach a human-readable name
    ./identify.py --list             # show what is already recorded
"""

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKETCH = os.path.join(HERE, "uid_probe")
INVENTORY = os.path.join(HERE, "boards.json")
BUILD_DIR = os.path.join(HERE, ".build")

# Coprocessor UID layout, 27 bytes. The header, chip type, batch number,
# firmware identifier and build number are per the Infineon solution reference
# manual; the single-byte wafer X/Y split is inferred from the byte budget
# (everything else is fixed-width and the total must come to 27).
UID_FIELDS = [
    ("cim_identifier",      0,  1),
    ("platform_identifier", 1,  2),
    ("model_identifier",    2,  3),
    ("rom_mask_id",         3,  5),
    ("chip_type",           5, 11),
    ("batch_number",       11, 19),
    ("wafer_x",            19, 20),
    ("wafer_y",            20, 21),
    ("firmware_identifier",21, 25),
    ("build_number",       25, 27),
]

# Firmware identifier is shared across revisions; the build number is what
# actually separates them.
BUILD_TO_REVISION = {
    "0809": ("V1", "1.30.809"),
    "2440": ("V3", "3.00.2440"),
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# RP2040 boards enumerate under the Raspberry Pi VID, or the vendor's own.
# A sketch built by this core reports 2e8a:8109 ("PicoArduino") even on an
# Adafruit board, so arduino-cli's vid+pid board match fails once the probe
# is flashed. Fall back to VID matching and a caller-supplied FQBN.
RP2040_VIDS = {"0x2e8a", "0x239a"}
DEFAULT_FQBN = "rp2040:rp2040:adafruit_trinkeyrp2040qt"


def find_board(fqbn_hint=None, port_hint=None):
    """Return (port, fqbn, usb_serial) for the connected RP2040 board."""
    proc = run(["arduino-cli", "board", "list", "--format", "json"])
    if proc.returncode != 0:
        sys.exit(f"arduino-cli board list failed:\n{proc.stderr}")

    payload = json.loads(proc.stdout)
    ports = payload.get("detected_ports", payload) if isinstance(payload, dict) else payload

    candidates = []
    for entry in ports:
        info = entry.get("port", {})
        address = info.get("address")
        props = info.get("properties", {}) or {}
        vid = (props.get("vid") or "").lower()

        if port_hint and address != port_hint:
            continue
        if info.get("protocol") != "serial":
            continue
        if not port_hint and vid not in RP2040_VIDS:
            continue

        # arduino-cli identifies the model only when vid+pid match boards.txt.
        matched = next((b.get("fqbn") for b in entry.get("matching_boards", []) or []
                        if "rp2040" in b.get("fqbn", "")), None)
        serial_no = props.get("serialNumber") or info.get("hardware_id") or usb_serial(address)
        candidates.append((address, matched, serial_no))

    if not candidates:
        sys.exit("No RP2040 board found. Is it plugged in?")
    if len(candidates) > 1:
        listed = ", ".join(c[0] for c in candidates)
        sys.exit(f"More than one RP2040 board connected ({listed}). Use --port to pick one.")

    address, matched, serial_no = candidates[0]
    fqbn = matched or fqbn_hint or DEFAULT_FQBN
    if not matched:
        print(f"  model not auto-detected (probe sketch reports a generic USB ID)"
              f" - assuming {fqbn}")
    return address, fqbn, serial_no


def usb_serial(port):
    proc = run(["udevadm", "info", "-q", "property", "-n", port])
    for line in proc.stdout.splitlines():
        if line.startswith("ID_SERIAL_SHORT="):
            return line.split("=", 1)[1]
    return None


def flash(port, fqbn):
    print(f"  flashing uid_probe to {port} (this overwrites the sketch on the board)")
    proc = run(["arduino-cli", "compile", "--fqbn", fqbn,
                "--libraries", os.path.expanduser("~/Arduino/libraries"),
                "--build-path", BUILD_DIR, SKETCH])
    if proc.returncode != 0:
        sys.exit(f"compile failed:\n{proc.stdout}\n{proc.stderr}")

    proc = run(["arduino-cli", "upload", "--fqbn", fqbn, "-p", port,
                "--input-dir", BUILD_DIR, SKETCH])
    if proc.returncode != 0:
        sys.exit(f"upload failed:\n{proc.stdout}\n{proc.stderr}")

    wait_for_port(port)


def wait_for_port(port, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(port):
            time.sleep(1.0)
            return True
        time.sleep(0.2)
    return False


def read_uid(port, samples=3, timeout=40):
    """Read the UID until `samples` consecutive reads agree.

    A single read is not trusted: a silently wrong UID is the worst failure
    mode here, because it is well-formed and gets recorded as a real board.
    Returns (uid_hex, agreeing_count) or (None, 0).
    """
    import serial

    if not wait_for_port(port):
        return None, 0
    try:
        ser = serial.Serial(port, 115200, timeout=1)
    except Exception as exc:
        print(f"  could not open {port}: {exc}")
        return None, 0

    run_value, run_len, disagreements = None, 0, 0
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = ser.readline().decode("utf-8", "replace").strip()
            if line.startswith("UID "):
                parts = line.split()
                if len(parts) != 3:
                    continue
                uid = parts[2].upper()
                if uid == run_value:
                    run_len += 1
                else:
                    if run_value is not None:
                        disagreements += 1
                        print(f"  ! read disagreed: {run_value} -> {uid}")
                    run_value, run_len = uid, 1
                if run_len >= samples:
                    if disagreements:
                        print(f"  warning: {disagreements} disagreement(s) before"
                              f" settling - treat this reading with suspicion")
                    return run_value, run_len
            elif line.startswith("ERR"):
                print(f"  board reported: {line}")
    finally:
        ser.close()

    if run_value is not None:
        print(f"  only {run_len} of {samples} agreeing reads before timeout")
    return None, 0


def decode_uid(uid_hex):
    raw = bytes.fromhex(uid_hex)
    if len(raw) != 27:
        raise ValueError(f"expected 27 bytes, got {len(raw)}")

    fields = {name: raw[start:end].hex().upper() for name, start, end in UID_FIELDS}
    revision, firmware = BUILD_TO_REVISION.get(fields["build_number"], ("unknown", "unknown"))
    fields["revision"] = revision
    fields["firmware_version"] = firmware
    return fields


def load_inventory():
    if os.path.exists(INVENTORY):
        with open(INVENTORY) as fh:
            return json.load(fh)
    return {"boards": []}


def save_inventory(data):
    with open(INVENTORY, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def show(record):
    d = record["optiga"]
    print(f"  label            {record.get('label') or '(unlabeled)'}")
    print(f"  OPTIGA UID       {d['uid']}")
    print(f"  revision         Trust M {d['revision']}  (firmware {d['firmware_version']})")
    print(f"  chip type        {d['chip_type']}")
    print(f"  batch number     {d['batch_number']}")
    print(f"  wafer X/Y        {d['wafer_x']} / {d['wafer_y']}")
    print(f"  fw identifier    {d['firmware_identifier']}  build {d['build_number']}")
    print(f"  agreeing reads   {record.get('agreeing_reads', '?')}")
    host = record.get("last_seen_host", record.get("host", {}))
    print(f"  last seen on     Trinkey {host.get('usb_serial')}")
    seen = record.get("hosts_seen", [])
    if len(seen) > 1:
        print(f"  hosts seen       {', '.join(seen)}")
    print(f"  FQBN             {host.get('fqbn')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", help="human-readable name for this board")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--flash", action="store_true", help="always reflash the probe first")
    group.add_argument("--no-flash", action="store_true", help="never write to the board")
    ap.add_argument("--list", action="store_true", help="show recorded boards and exit")
    ap.add_argument("--fqbn", help=f"board FQBN (default {DEFAULT_FQBN})")
    ap.add_argument("--port", help="serial port, if more than one board is connected")
    ap.add_argument("--samples", type=int, default=3,
                    help="consecutive agreeing reads required (default 3)")
    args = ap.parse_args()

    inventory = load_inventory()

    if args.list:
        if not inventory["boards"]:
            print("No boards recorded yet.")
        for i, record in enumerate(inventory["boards"], 1):
            print(f"\n[{i}]")
            show(record)
        return

    port, fqbn, serial_no = find_board(args.fqbn, args.port)
    print(f"Found {fqbn} on {port} (RP2040 serial {serial_no})")

    if args.flash:
        flash(port, fqbn)

    uid_hex, agreed = read_uid(port, args.samples)

    if uid_hex is None and not args.flash and not args.no_flash:
        print("  no UID seen - the probe sketch is probably not on this board")
        flash(port, fqbn)
        uid_hex, agreed = read_uid(port, args.samples)

    if uid_hex is None:
        sys.exit("Could not read a UID. Try --flash, or check the shield is seated.")

    decoded = decode_uid(uid_hex)
    decoded["uid"] = uid_hex

    record = {
        "label": args.label,
        "recorded": time.strftime("%Y-%m-%d %H:%M:%S"),
        "optiga": decoded,
        "agreeing_reads": agreed,
        # Shields move between host boards, so this is where it was last seen,
        # not an identity. hosts_seen accumulates every Trinkey it has run on.
        "last_seen_host": {"usb_serial": serial_no, "fqbn": fqbn, "port": port},
        "hosts_seen": [serial_no] if serial_no else [],
    }

    # Key on the OPTIGA UID: the shield is the thing being identified.
    existing = next((b for b in inventory["boards"]
                     if b["optiga"]["uid"] == uid_hex), None)

    if args.label:
        clash = next((b for b in inventory["boards"]
                      if b.get("label") == args.label
                      and b["optiga"]["uid"] != uid_hex), None)
        if clash:
            sys.exit(f"Label {args.label!r} is already on shield "
                     f"{clash['optiga']['uid']}. Pick another, or relabel that one first.")
    if existing:
        print("\nAlready recorded - updating:")
        record["label"] = args.label or existing.get("label")
        seen = list(existing.get("hosts_seen", []))
        if serial_no and serial_no not in seen:
            seen.append(serial_no)
            print(f"  note: first time this shield has been seen on Trinkey {serial_no}")
        record["hosts_seen"] = seen or record["hosts_seen"]
        inventory["boards"][inventory["boards"].index(existing)] = record
    else:
        print("\nNew board:")
        inventory["boards"].append(record)

    show(record)
    save_inventory(inventory)
    print(f"\nSaved to {INVENTORY} ({len(inventory['boards'])} board(s) recorded)")


if __name__ == "__main__":
    main()
