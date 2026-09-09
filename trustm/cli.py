"""
Command line for the Trust M bridge.

    python -m trustm ports
    python -m trustm flash
    python -m trustm ping
    python -m trustm uid
    python -m trustm rand 32
    python -m trustm rand 1024 --source drng --raw > bytes.bin
    python -m trustm read E0E0 --raw > cert.der
    python -m trustm write F1D0 DEADBEEF
    python -m trustm cert --verify
    python -m trustm cert --pem > device.pem
    python -m trustm keygen E0F1 --pem > key.pem
    python -m trustm sign --file report.txt > sig.der
    python -m trustm meta E0E0
    python -m trustm meta --all
    python -m trustm hash --file report.txt
    python -m trustm counter E120 --increment
"""

import argparse
import os
import subprocess
import sys

from . import __version__, const
from .device import TrustM
from .errors import TrustMError
from .transport import find_ports

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKETCH = os.path.join(ROOT, "firmware", "trustm_bridge")
BUILD_DIR = os.path.join(ROOT, "firmware", ".build")
DEFAULT_FQBN = "rp2040:rp2040:adafruit_trinkeyrp2040qt"
LIBRARIES = os.path.expanduser("~/Arduino/libraries")


def wire_logger(stream=sys.stderr):
    def log(line):
        print(line, file=stream)
    return log


def open_device(args):
    log = wire_logger() if args.verbose else None
    return TrustM(port=args.port, timeout=args.timeout, log=log)


# ------------------------------------------------------------------ commands


def cmd_ports(args):
    ports = find_ports()
    if not ports:
        print("No RP2040 board found.")
        return 1
    for port in ports:
        serial_no = port.serial_number or "?"
        print(f"{port.device}  {port.vid:04x}:{port.pid:04x}  {serial_no}  "
              f"{port.description}")
    return 0


def cmd_flash(args):
    """Build and upload the bridge firmware. This overwrites the sketch."""
    fqbn = args.fqbn
    port = args.port
    if port is None:
        ports = find_ports()
        if len(ports) != 1:
            print("Pass --port: found "
                  f"{len(ports)} RP2040 boards.", file=sys.stderr)
            return 1
        port = ports[0].device

    print(f"building {SKETCH}")
    build = subprocess.run(["arduino-cli", "compile", "--fqbn", fqbn,
                            "--libraries", LIBRARIES,
                            "--build-path", BUILD_DIR, SKETCH])
    if build.returncode != 0:
        return build.returncode

    print(f"uploading to {port} (this overwrites the sketch on the board)")
    upload = subprocess.run(["arduino-cli", "upload", "--fqbn", fqbn,
                             "-p", port, "--input-dir", BUILD_DIR, SKETCH])
    if upload.returncode != 0:
        return upload.returncode

    # An upload can report success while the board carries on running the old
    # firmware - see bridge-plan.md section 4. Say so rather than let a silent
    # board look like a hardware fault.
    print("uploaded. If the board does not answer PING, upload a second time:"
          " uploads can race USB re-enumeration.")
    return 0


def cmd_ping(args):
    with open_device(args) as device:
        # check=False: a board running the wrong protocol is exactly what ping
        # is for, so report it rather than refusing to speak.
        info = device.ping(check=False)
        print(info)
        if info.proto != const.PROTO_VERSION:
            print(f"warning: this package speaks protocol "
                  f"{const.PROTO_VERSION}; reflash with `python -m trustm flash`",
                  file=sys.stderr)
    return 0


def cmd_commands(args):
    with open_device(args) as device:
        for name in sorted(device.commands()):
            print(name)
    return 0


def cmd_uid(args):
    with open_device(args) as device:
        uid = device.uid()
        print(uid.hex)
        print(f"  {uid}")
        for name, value in uid.fields.items():
            print(f"  {name:<20} {value}")
    return 0


def cmd_rand(args):
    with open_device(args) as device:
        data = device.random(args.length, source=args.source)
    if args.raw:
        sys.stdout.buffer.write(data)
    else:
        print(data.hex().upper())
    return 0


def plural(n, noun="byte"):
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _curve_names():
    """Deferred so that --help works without `cryptography` installed."""
    from .keys import CURVE_NAMES
    return CURVE_NAMES


def parse_oid(text):
    """Accept 'E0C2', '0xE0C2', or a name from the library's own enum."""
    name = text.upper()
    if name in const.OIDS:
        return const.OIDS[name]
    try:
        return int(text, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a hex OID or one of: "
            f"{', '.join(sorted(const.OIDS))}") from None


def cmd_meta(args):
    from . import metadata as meta

    with open_device(args) as device:
        if args.all:
            found = device.objects()
        elif args.oid is None:
            print("error: give an OID, or --all", file=sys.stderr)
            return 1
        else:
            found = {args.oid: device.metadata(args.oid)}

    for oid, m in found.items():
        if args.raw:
            print(f"{oid:04X} {m.raw.hex().upper()}")
            continue
        name = _oid_name(oid)
        print(f"{m}" + (f"   ({name})" if name else ""))

    if args.all:
        sys.stdout.flush()
        locked = sum(1 for m in found.values() if m.locked)
        print(f"{plural(len(found), 'object')}, {locked} permanently locked",
              file=sys.stderr)
    return 0


def _oid_name(oid):
    """What this object is, preferring the description over the enum name."""
    if oid in const.KNOWN_OIDS:
        return const.KNOWN_OIDS[oid]
    for name, value in const.OIDS.items():
        if value == oid:
            return name
    return None


def cmd_cert(args):
    from . import cert as certmod

    with open_device(args) as device:
        data = device.read_data(args.oid)

    if certmod.is_empty(data):
        sys.stdout.flush()
        print(f"0x{args.oid:04X} is empty ({plural(len(data))}, all zero)",
              file=sys.stderr)
        return 1

    try:
        chain = certmod.load_chain(data)
    except certmod.CertificateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.der:
        sys.stdout.buffer.write(certmod.split_container(data)[0])
        return 0
    if args.pem:
        for one in chain:
            sys.stdout.write(certmod.to_pem(one))
        return 0

    leaf = chain[0]
    print(f"0x{args.oid:04X}  {len(data)} bytes, {plural(len(chain), 'certificate')}")
    for label, value in certmod.describe(leaf):
        print(f"  {label:<12} {value}")

    if not args.verify:
        return 0

    cas = certmod.load_cas()
    if args.ca_dir:
        cas += certmod.load_cas(args.ca_dir)
    # Certificates that came out of the chip's own object are as good as any
    # file for completing the chain, so they go in the store too.
    cas += [("(from the chip)", c) for c in chain[1:]]

    print(f"\nchain, against {plural(len(cas), 'CA')}:")
    steps = certmod.build_chain(leaf, cas)
    for i, step in enumerate(steps):
        subject = step["cert"].subject.rfc4514_string()
        print(f"  {i}. {subject[:66]}")
        if step["verified"] is None:
            print(f"     issuer {step['cert'].issuer.rfc4514_string()[:52]}")
            print(f"     NOT FOUND in the store")
        else:
            mark = "verified" if step["verified"] else "SIGNATURE DID NOT VERIFY"
            root = "  [self-signed root]" if step["self_signed"] else ""
            print(f"     signed by {step['issuer_file']} -> {mark}{root}")

    if certmod.chain_is_complete(steps):
        print("\ncomplete: every link verified, up to a self-signed root")
        return 0
    sys.stdout.flush()
    print("\nincomplete: the chain stops where it does above", file=sys.stderr)
    return 1


def parse_slot(text):
    """A key slot: a hex OID, or the words the chip understands."""
    if text.lower() in ("session", "export"):
        return text.lower()
    return parse_oid(text)


def cmd_keygen(args):
    from . import keys as keymod

    with open_device(args) as device:
        try:
            pair = device.generate_keypair(args.slot, curve=args.curve,
                                           usage=args.usage,
                                           allow_provisioned=args.allow_provisioned)
        except ValueError as exc:
            # generate_keypair phrases its refusal for a Python caller.
            if (not args.allow_provisioned
                    and args.slot in const.PROVISIONED_KEY_SLOTS):
                print(f"error: 0x{args.slot:04X} holds the "
                      f"{const.PROVISIONED_KEY_SLOTS[args.slot]}, and overwriting "
                      f"it destroys the identity E0E0's certificate attests to. "
                      f"Pass --allow-provisioned if you mean it.", file=sys.stderr)
                return 1
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.pem:
        sys.stdout.write(keymod.public_pem(pair.public_key))
        if pair.private is not None:
            sys.stdout.flush()
            print("note: the private key was exported; it is NOT in this PEM",
                  file=sys.stderr)
        return 0

    print(pair.public.hex().upper())
    if pair.private is not None:
        print(pair.private.hex().upper())
    sys.stdout.flush()
    print(f"{pair}", file=sys.stderr)
    return 0


def cmd_sign(args):
    from . import keys as keymod

    size = keymod.digest_size(args.curve)
    algorithm = "sha256" if size == 32 else "sha384"

    if args.file:
        import hashlib
        digest = hashlib.new(algorithm)
        with open(args.file, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        digest = digest.digest()
    elif args.digest is None:
        print("error: pass a digest as hex, or use --file", file=sys.stderr)
        return 1
    else:
        try:
            digest = bytes.fromhex(args.digest)
        except (TypeError, ValueError):
            print("error: DIGEST must be hex, or use --file", file=sys.stderr)
            return 1
        if len(digest) != size:
            print(f"error: {args.curve} signs a {size}-byte digest, got "
                  f"{plural(len(digest))}", file=sys.stderr)
            return 1

    with open_device(args) as device:
        signature = device.sign(digest, slot=args.slot)

    if args.raw:
        sys.stdout.buffer.write(signature)
        return 0
    print(signature.hex().upper())
    sys.stdout.flush()
    print(f"{algorithm} digest {digest.hex().upper()[:32]}..., "
          f"{plural(len(signature))} of DER signature", file=sys.stderr)
    return 0


def cmd_hash(args):
    data = None
    if not args.file:
        if args.data is None:
            print("error: pass the bytes as hex, or use --file", file=sys.stderr)
            return 1
        try:
            data = bytes.fromhex(args.data)
        except (TypeError, ValueError):
            print("error: DATA must be hex, or use --file", file=sys.stderr)
            return 1

    with open_device(args) as device:
        # A file is streamed rather than read into memory first, so this works
        # on something larger than the host wants to hold.
        digest = device.hash_file(args.file) if args.file else device.hash(data)
    print(digest.hex().upper())

    if args.check:
        import hashlib
        if args.file:
            host = hashlib.sha256()
            with open(args.file, "rb") as handle:
                for block in iter(lambda: handle.read(65536), b""):
                    host.update(block)
            host = host.digest()
        else:
            host = hashlib.sha256(data).digest()
        sys.stdout.flush()
        print(f"host sha256: {'matches' if host == digest else 'DIFFERS'}",
              file=sys.stderr)
        return 0 if host == digest else 1
    return 0


def cmd_counter(args):
    with open_device(args) as device:
        if args.set is not None:
            device.set_counter(args.oid, value=0, threshold=args.set)
        if args.increment:
            value, threshold = device.increment_counter(args.oid, args.step)
        else:
            value, threshold = device.counter(args.oid)

    print(f"{value}/{threshold}")
    sys.stdout.flush()
    if args.increment and value == threshold:
        print(f"0x{args.oid:04X} is at its threshold; the next increment fails",
              file=sys.stderr)
    return 0


def cmd_read(args):
    with open_device(args) as device:
        data = device.read_data(args.oid, offset=args.offset, length=args.length)
    if args.raw:
        sys.stdout.buffer.write(data)
    else:
        print(data.hex().upper())
        sys.stdout.flush()
        print(f"{plural(len(data))} from 0x{args.oid:04X}", file=sys.stderr)
    return 0


def cmd_write(args):
    if args.file:
        with open(args.file, "rb") as handle:
            data = handle.read()
    elif args.data is None:
        print("error: pass the bytes as hex, or use --file", file=sys.stderr)
        return 1
    else:
        try:
            data = bytes.fromhex(args.data)
        except (TypeError, ValueError):
            print("error: DATA must be hex, or use --file", file=sys.stderr)
            return 1

    with open_device(args) as device:
        try:
            written = device.write_data(args.oid, data, offset=args.offset,
                                        erase=not args.no_erase,
                                        allow_provisioned=args.allow_provisioned)
        except ValueError as exc:
            # write_data phrases its refusal for a Python caller; from here the
            # thing to reach for has a different name.
            if not args.allow_provisioned and args.oid in const.PROVISIONED_OIDS:
                print(f"error: 0x{args.oid:04X} holds the "
                      f"{const.PROVISIONED_OIDS[args.oid]}, and overwriting it "
                      f"cannot be undone. Pass --allow-provisioned if you mean it.",
                      file=sys.stderr)
                return 1
            raise
    sys.stdout.flush()
    print(f"{plural(written)} to 0x{args.oid:04X}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------- main


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m trustm",
        description="Talk to an OPTIGA Trust M through a Trinkey running "
                    "the trustm_bridge firmware.")
    parser.add_argument("--version", action="version",
                        version=f"trustm {__version__}")
    parser.add_argument("-p", "--port",
                        help="serial port (default: the only RP2040 found)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0,
                        help="seconds to wait for a reply (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print the wire traffic to stderr")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ports", help="list connected RP2040 boards").set_defaults(
        func=cmd_ports)

    flash = sub.add_parser("flash", help="build and upload the bridge firmware")
    flash.add_argument("--fqbn", default=DEFAULT_FQBN)
    flash.set_defaults(func=cmd_flash)

    sub.add_parser("ping", help="firmware version and limits").set_defaults(
        func=cmd_ping)

    sub.add_parser("uid", help="read and decode the coprocessor UID").set_defaults(
        func=cmd_uid)

    sub.add_parser("commands", help="what this firmware supports").set_defaults(
        func=cmd_commands)

    rand = sub.add_parser("rand", help="read random bytes from the chip")
    rand.add_argument("length", type=int, nargs="?",
                      default=const.RAND_LEN_DEFAULT,
                      help=f"how many bytes (default {const.RAND_LEN_DEFAULT})")
    rand.add_argument("--source", choices=sorted(const.RNG_TYPES), default="trng")
    rand.add_argument("--raw", action="store_true",
                      help="write the bytes to stdout instead of hex")
    rand.set_defaults(func=cmd_rand)

    metap = sub.add_parser("meta", help="read an object's metadata")
    metap.add_argument("oid", type=parse_oid, nargs="?",
                       help="the object; omit with --all")
    metap.add_argument("--all", action="store_true",
                       help="every object the chip has")
    metap.add_argument("--raw", action="store_true",
                       help="the undecoded TLV as hex")
    metap.set_defaults(func=cmd_meta)

    cert = sub.add_parser("cert", help="read and parse a certificate object")
    cert.add_argument("oid", type=parse_oid, nargs="?", default=0xE0E0,
                      help="certificate object (default E0E0)")
    cert.add_argument("--verify", action="store_true",
                      help="follow the chain through the bundled Infineon CAs")
    cert.add_argument("--ca-dir", help="a directory of extra CA certificates")
    cert.add_argument("--pem", action="store_true", help="write PEM to stdout")
    cert.add_argument("--der", action="store_true",
                      help="write the leaf certificate as DER to stdout")
    cert.set_defaults(func=cmd_cert)

    keygen = sub.add_parser("keygen", help="generate an ECC keypair")
    keygen.add_argument("slot", type=parse_slot, nargs="?", default=0xE0F1,
                        help="key slot, 'session', or 'export' (default E0F1)")
    keygen.add_argument("--curve", choices=list(_curve_names()), default="p256")
    keygen.add_argument("--usage", default="sign",
                        help="sign, auth, agree, encrypt - join with '+'")
    keygen.add_argument("--pem", action="store_true",
                        help="write the public key as PEM instead of hex")
    keygen.add_argument("--allow-provisioned", action="store_true",
                        help="permit E0F0, destroying the factory identity")
    keygen.set_defaults(func=cmd_keygen)

    sign = sub.add_parser("sign", help="ECDSA-sign a digest")
    sign.add_argument("digest", nargs="?", help="the digest as hex")
    sign.add_argument("--file", help="hash this file and sign the digest")
    sign.add_argument("--slot", type=parse_slot, default=0xE0F1,
                      help="key slot or 'session' (default E0F1)")
    sign.add_argument("--curve", choices=list(_curve_names()), default="p256",
                      help="which digest size to expect (default p256/sha256)")
    sign.add_argument("--raw", action="store_true",
                      help="write DER bytes to stdout instead of hex")
    sign.set_defaults(func=cmd_sign)

    hashp = sub.add_parser("hash", help="SHA-256, computed on the chip")
    hashp.add_argument("data", nargs="?", help="the bytes as hex")
    hashp.add_argument("--file", help="hash this file instead")
    hashp.add_argument("--check", action="store_true",
                       help="also hash on the host and compare")
    hashp.set_defaults(func=cmd_hash)

    counter = sub.add_parser("counter", help="read or bump a monotonic counter")
    counter.add_argument("oid", type=parse_oid, help="E120 to E123")
    counter.add_argument("--increment", action="store_true", help="bump it")
    counter.add_argument("--step", type=int, default=1, help="by how much (1-255)")
    counter.add_argument("--set", type=int, metavar="THRESHOLD",
                         help="reset to 0 with this threshold first")
    counter.set_defaults(func=cmd_counter)

    read = sub.add_parser("read", help="read a data object")
    read.add_argument("oid", type=parse_oid, help="hex OID, e.g. E0E0")
    read.add_argument("--offset", type=int, default=0)
    read.add_argument("--length", type=int, default=None,
                      help="bytes to read (default: to the end of the object)")
    read.add_argument("--raw", action="store_true",
                      help="write the bytes to stdout instead of hex")
    read.set_defaults(func=cmd_read)

    write = sub.add_parser("write", help="write a data object")
    write.add_argument("oid", type=parse_oid, help="hex OID, e.g. F1D0")
    write.add_argument("data", nargs="?", help="bytes as hex")
    write.add_argument("--file", help="read the bytes from a file instead")
    write.add_argument("--offset", type=int, default=0)
    write.add_argument("--no-erase", action="store_true",
                       help="patch in place, leaving the rest of the object")
    write.add_argument("--allow-provisioned", action="store_true",
                       help="permit writing E0F0/E0E0. This is irreversible.")
    write.set_defaults(func=cmd_write)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TrustMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
