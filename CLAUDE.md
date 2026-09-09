# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A subproject of `~/git/randomness` ("Research, resources, visualizations, and
presentation on randomness"). It explores an **Infineon OPTIGA Trust M**
security chip attached to an **Adafruit Trinkey RP2040 QT** over I2C.

The starting point was Adafruit's TRNG gadget — the chip's hardware RNG dumped
over USB serial. The goal is to reach the rest of the chip's feature set from
the desktop.

**`bridge-plan.md` is the plan of record.** Read it before designing anything.
It settles the architecture (host library stays on the microcontroller; the
desktop drives it over USB CDC with a line-oriented command protocol), and
records the wire format, command set, Python package layout, build order and
guard rails.

The other three documents are for humans, and are where a change to behaviour
has to be reflected: `README.md` summarises the project, `trustm.md` documents
using it (command line, Python API, data objects, wire protocol, architecture),
`build.md` documents building and flashing it.

## Hardware facts that constrain everything

**The chips are Trust M V1, firmware 1.30.809 — not V3.** This is the single
most important thing to know. V1 has **no on-chip symmetric crypto**: no AES,
HMAC, HKDF, or `generate_auth_code`. Those are V3 silicon features. Do not
propose them, and do not suggest upgrading the host library to get them — the
bundled v1.30.885 already matches this silicon's firmware.

What V1 does have: TRNG/DRNG, **SHA-256 only**, ECC P-256/P-384 (keygen, ECDSA,
ECDH), RSA 1024/2048 PKCS#1 v1.5 only, TLS PRF SHA-256, data objects, metadata,
monotonic counters, protected update. Full table in `bridge-plan.md` §2.

Note that `testAES128CCMEncrypt` in `OPTIGATrustM.cpp` is **mbedTLS on the
RP2040**, not the chip — it calls `pal_crypt_encrypt_aes128_ccm`.

**A shield is not bound to a Trinkey — they get swapped around.** The OPTIGA
Coprocessor UID identifies the *shield*; the RP2040 USB serial identifies the
*Trinkey*. Never treat a pairing as fixed — `boards.json` records the host as
`last_seen_host`. That file is gitignored (real UIDs and USB serials are unique
hardware identifiers); `boards.example.json` shows its shape.

**Shields bought together are likely wafer-lot siblings.** Two here differ in
only 2 of 27 UID bytes (batch-number tail and wafer Y), so a swapped shield
looks almost exactly like a corrupted read of the other one. This has already
caused one real mix-up. Never identify a board from a single read.

## Commands

There is no test suite or linter. The build system is `arduino-cli` for the
firmware; the host package is plain Python needing only `pyserial`.

```bash
# Drive the chip from the desktop (needs the bridge firmware on the board)
python -m trustm ports          # what is connected
python -m trustm flash          # build and upload firmware/trustm_bridge
python -m trustm ping           # firmware version and limits; does not touch the chip
python -m trustm uid            # read and decode the coprocessor UID
python -m trustm rand 32        # random bytes as hex (TRNG unless --source drng)
python -m trustm rand           # 64 bytes, the same default the firmware uses
python -m trustm commands       # ask the board what it supports (the HELP command)
python -m trustm meta --all     # every object: sizes, lifecycle, access conditions
python -m trustm cert --verify  # parse E0E0 and follow the chain
python -m trustm keygen E0F1 --pem > key.pem     # key generated inside the chip
python -m trustm sign --file report.txt --raw > sig.der
python -m trustm hash --file report.txt --check   # chip SHA-256 vs the host's
python -m trustm counter E120 --set 100 --increment
python -m trustm read E0E0      # read a data object, chunked as needed
python -m trustm write F1D0 DEADBEEF     # replaces the object; --no-erase patches
python -m trustm -v uid         # also print the wire traffic to stderr

# Regenerate constants after the Arduino library changes
./tools/gen_const.py            # rewrite trustm/_generated.py
./tools/gen_const.py --check    # exit 1 if it is stale

# Identify whichever shield is connected (flashes the probe only if needed)
cd trustm_boards && ./identify.py --label "spare"
./identify.py --list            # show recorded boards
./identify.py --samples 5       # require more agreeing reads (default 3)
./identify.py --no-flash        # never write to the board
./identify.py --flash           # force a reflash first

# Build and upload a sketch by hand
arduino-cli compile --fqbn rp2040:rp2040:adafruit_trinkeyrp2040qt \
  --libraries ~/Arduino/libraries --build-path .build <sketch-dir>
arduino-cli upload --fqbn rp2040:rp2040:adafruit_trinkeyrp2040qt \
  -p /dev/ttyACM0 --input-dir .build <sketch-dir>

# Watch serial output
python3 -c "
import serial
ser = serial.Serial('/dev/ttyACM0', 115200, timeout=1)
while True:
    line = ser.readline().decode('utf-8','replace').strip()
    if line: print(line)"
```

Host tooling in place: arduino-cli 1.5.1, pyserial 3.5, cryptography 49.0.0.
`cryptography` is what makes desktop-side verification of chip signatures and
certificates cheap — use it rather than hand-rolling ASN.1.

## The Arduino library is a symlink into this repo — do not reinstall it

`~/Arduino/libraries/OPTIGA_Trust_M` is a **symlink** to
`subs/arduino-optiga-trust-m`, which carries local patches. Installing or
updating the library through the Arduino IDE's Library Manager will replace the
symlink and silently revert those fixes, breaking the build.

The patches fix six `pal_status_t` functions that fell off the end without a
return (a hard error under the rp2040 core's `-Werror=return-type`) plus one
`-Wwrite-strings` warning. They are captured in
`patches/0001-fix-pal-return-types.patch`. After any `git submodule update` that
resets the submodule, re-apply it:

```bash
cd subs/arduino-optiga-trust-m && patch -p1 < ../../patches/0001-fix-pal-return-types.patch
```

`git -C subs/arduino-optiga-trust-m diff --stat` should show exactly three
files. `~/Arduino/libraries/OPTIGA_Trust_M.bak` is the original Library Manager
copy, kept as a fallback.

## Architecture of the Infineon stack

Understanding where to cut is the whole design question, and it takes reading
several files to see. The host library layers, top to bottom:

```
OPTIGATrustM.cpp        Arduino C++ wrapper - only surfaces a SLICE of the API
optiga_util / crypt     the real public API, asynchronous (callback + poll)
optiga_cmd              command/APDU construction
optiga_comms_ifx_i2c    Infineon shielded-connection transport
ifx_i2c_*_layer         presentation / transport / data link / physical
pal_*_arduino.cpp       platform abstraction - I2C, GPIO, timer, logger
```

Two consequences that matter constantly:

1. **The `trustM.*` C++ wrapper is not the API.** It covers a fraction of what
   the chip does. Drop to `optiga_util_*` / `optiga_crypt_*` in
   `src/optiga_trustm/` whenever the wrapper falls short. The wrapper's value is
   that it synchronises the async callback API for you; when calling the core
   API directly you must handle `optiga_lib_status` polling yourself.

2. **Do not bridge at the `pal_i2c` layer.** The physical layer does polling
   loops, guard times and per-frame retries with real timing assumptions.
   Tunnelling individual I2C transactions over USB adds a round trip to every
   one of them. If a desktop-side host library is ever wanted, split at the
   `optiga_comms` boundary instead — one round trip per APDU. `bridge-plan.md`
   §3 covers this.

Config lives in `src/optiga_trustm/optiga_lib_config.h`:
`OPTIGA_MAX_COMMS_BUFFER_SIZE` = 1557 bytes caps any single transfer, and
shielded connection defaults to `OPTIGA_COMMS_NO_PROTECTION`. Leave it there —
enabling it needs a platform binding secret in E140 and only makes debugging
harder.

## Chip state you can destroy permanently

- **E0F0 / E0E0 are factory-provisioned** — the Infineon attestation key and its
  matching certificate. The chip's own metadata marks E0F0 `change: never`, but
  do not rely on that as the only guard. Use E0F1 for experiments.
- **Lifecycle state is one-way.** `LCS_G` (E0C0) and `LCS_A` (F1C0) go
  creation → initialization → operational → termination and never back. E0F1–E0F3
  become immutable once the state passes `operational`.
- **The security monitor throttles the chip** after repeated failing operations.
  Read the security event counter (E0C5) when things inexplicably slow down.

## Environment traps

These have all bitten already; see `bridge-plan.md` §4 for detail.

- **Arduino IDE 2 is a Flatpak** (`cc.arduino.IDE2`) and cannot upload to RP2040
  without `flatpak override --user --filesystem=/run/media cc.arduino.IDE2`. The
  core's `uf2conv.py` calls `udisksctl`, which is absent from the runtime; the
  fix makes its `/run/media` fallback scan work instead. The
  `Exception executing udisksctl` line still prints and is cosmetic. It depends
  on GNOME automount, so it fails with the screen locked — `arduino-cli` from a
  terminal has no such dependency.
- **Uploads can race USB re-enumeration.** An upload reported success while the
  board kept running its previous firmware; an identical second upload took
  effect. A silent board after flashing is usually this, not a hardware fault.
- **USB IDs are not consistent between boards** — one Trinkey here enumerates as
  `239a:8109` and `arduino-cli` names it correctly, the other as `2e8a:8109`
  (`PicoArduino`) from what should be an identical build, which defeats
  `arduino-cli`'s vid+pid match. Cause not established. Don't rely on
  `arduino-cli board list` naming the model; `identify.py` accepts either.

## Reference material is already vendored — prefer it over the web

| what | where |
|---|---|
| Solution Reference Manual v3.70, **greppable markdown**, covers the V1/V3 split | `subs/optiga-trust-m-overview/docs/OPTIGA™ Trust M Solution Reference Manual.md` |
| Config Guide, Datasheet, Keys & Certificates, I2C Protocol v2.03 (PDF) | `subs/optiga-trust-m-overview/docs/pdf/` |
| **Factory metadata dump from V1 silicon** — ground truth for access conditions | `subs/optiga-trust-m-overview/data/object_dumps/trust_m1_json.txt` |
| **Infineon root/intermediate CAs** — needed to verify the E0E0 cert chain | `subs/optiga-trust-m-overview/data/certificates/` |
| Arduino wrapper class reference | `reference/` |
| Trinkey datasheets, original TRNG gadget sketch and its prebuilt UF2s | `archive/adafruit/` |

`archive/` holds what this project does not build on: the original Adafruit
TRNG gadget, and four Infineon repos moved out of `subs/`
(`linux-optiga-trust-m`, `optiga-trust-m-openssl`, `pkcs11-optiga-trust-m`,
which all assume a real `/dev/i2c-N` and cannot be reached through a Trinkey,
plus `optiga-trust-m`, the upstream of the Arduino port). They are still
submodules, just at `archive/subs/`. Don't propose using them without a
USB-I2C bridge (MCP2221A, FT260) or a Raspberry Pi. `archive/README.md`
explains each.

## Existing code

- `firmware/trustm_bridge/trustm_bridge.ino` — the bridge firmware. A
  line-oriented command dispatcher over USB CDC; `PING`, `UID`, `RAND` (with
  `TRNG`/`DRNG` aliases), `RDATA`, `WDATA`, `RMETA`, `WMETA`, `KEYGEN`, `SIGN`,
  `VERIFY`, `HASH` (plus streaming `HASHSTART`/`HASHUPD`/`HASHFIN`), `ECDH`,
  `CTRINC`, `RSAGEN`, `RSASIGN` and `HELP` (alias `?`) are implemented — the
  whole build order. It calls `optiga_util_*` / `optiga_crypt_*` directly rather than
  going through the `IFX_OPTIGA_TrustM` wrapper, for the reasons in the
  Architecture section — and so it never runs the wrapper's `pairMCU()`, which
  `begin()` does by default and which writes a platform binding secret.
  Bridge-level failures use `0xFFxx` status codes; keep them in step with
  `trustm/const.py`'s `BRIDGE_ERRORS`.
- `trustm/` — the host package. `transport.py` (framing, correlation tags,
  resync), `cert.py` (the E0E0 container and chain verification), `keys.py`
  (the two encodings below), `metadata.py` (the object metadata TLV), `raw.py` (one function per command, bytes in/out), `device.py` (the
  `TrustM` class, which chunks and parses), `errors.py`, `cli.py`.
- `trustm/_generated.py` is written by `tools/gen_const.py` from the headers in
  `subs/arduino-optiga-trust-m` — **do not hand-edit it**. Hand-maintained
  constants go in `const.py`, which re-exports it; that is where the chip's own
  SRM error-code table lives, since it exists in no C header.
- `trustm_boards/` — `identify.py` (board inventory, keyed on OPTIGA UID),
  `uid_probe/uid_probe.ino` (prints the UID on a repeating loop; the stock
  `getUniqueID` example prints once and halts, which races re-enumeration after
  a flash), `boards.json`. This predates the bridge and still drives the probe
  sketch; it is the only thing that insists on several agreeing UID reads.
- `archive/` — what the project no longer builds on, with a README explaining
  each item. The original Adafruit TRNG gadget is in `archive/adafruit/`.

The two flashing paths — `python -m trustm flash` and `identify.py --flash` —
overwrite each other, since a board holds one sketch. Both hardcode
`~/Arduino/libraries`.

`RAND` is capped at 8-256 bytes per call by the chip (SRM 4.4.1.6). The
firmware enforces that; `TrustM.random()` chunks and pads around it. Don't
"fix" the firmware limit — it is the chip's.

`RAND`'s two arguments are independently optional: the length is found by
starting with a digit, not by position, so `RAND drng` is 64 DRNG bytes and
`RAND 32x` is still `E_ARGS` rather than a silent 32. `TRNG`/`DRNG` are `RAND`
with the source fixed and take a length only.

## Three encodings that are not what their names suggest

Each of these fails a long way from its cause. All three are handled; none
should be "fixed" in the firmware, because the firmware's job is to report what
the chip actually said.

1. **E0E0 is not a certificate.** It is a TLS-style container — `C0 <u16>
   <u24 list-len> <u24 cert-len> <DER>` — nine bytes in front of the DER.
   `openssl x509 -inform der` appears to work because it reads the first DER
   structure and ignores the header; `cryptography` refuses. `cert.py` parses
   it properly rather than slicing `[9:]`.
2. **A KEYGEN public key is a bare DER BIT STRING**, `03 42 00 04 || X || Y`,
   with no AlgorithmIdentifier — nothing in it says which curve it is, so the
   caller must remember what it asked for.
3. **A SIGN signature has no outer SEQUENCE.** The chip emits r and s as two
   INTEGERs and stops. Every verifier rejects that, and it looks like a bad
   signature rather than a framing problem. `keys.der_signature()` wraps it and
   is idempotent; `TrustM.sign()` returns the wrapped form, `raw.sign()` the
   chip's own bytes.

`KEYGEN`'s `export` sits in the slot position, not as a trailing flag, because
`export_private_key = TRUE` turns the API's `private_key` argument from an OID
into a buffer — a key is either kept in the chip or handed to the host. That
call also never reports how many bytes it wrote into the export buffer, so the
firmware sizes it for the largest key and recovers the length from the DER.

Guards, same pattern as WDATA: the firmware writes any slot it is told to, and
`TrustM.generate_keypair()` refuses **E0F0** unless `allow_provisioned=True`.
E0F1-E0F3 are the experiment slots; `session` is volatile and safest.

## Metadata, and what cannot be undone

`RMETA`/`WMETA` reach the object metadata TLV; `trustm/metadata.py` decodes it
against the SRM's tables, validated against the 41-object V1 factory dump in
`subs/optiga-trust-m-overview/data/object_dumps/`. **Reading metadata is always
permitted**, even for objects whose contents are not readable — so it is the
way to find out *why* a read was refused.

`WMETA` merges: writing one tag leaves the others alone. Three of the changes
it can make are permanent, and the chip enforces none of them, so
`TrustM.write_metadata()` refuses each unless told otherwise:

- **`lcso`** — lifecycle only ever moves forward. E0F1-E0F3 carry `change:
  lcso < operational`, so advancing theirs to operational makes them immutable
  for good. Needs `allow_lifecycle=True`.
- **any access condition set to NEV** locks that operation out permanently.
  Needs `allow_lock=True`.
- **E0F0 and E0E0** metadata is part of the factory identity. Needs
  `allow_provisioned=True`.

`const.KNOWN_OIDS` is the full 42-object list. Do not use `const.OIDS` for a
survey — the library's `eOID_d` enum has no name for the counters, the trust
anchors, the platform binding secret or any of the general-purpose data
objects, and covers only 20 of them.

**The probe sketch pairs the MCU.** `trustm_boards/uid_probe` calls
`trustM.begin()`, and the wrapper's signature is `begin(uint8_t pairDevice = 1)`
— pairing is the default, and `pairMCU()` writes a platform binding secret into
E140. A board that had run the probe shows it: E140 is `lcso=initialization`
where the factory dump has `creation`. Harmless here, but it is a write to a security object by a sketch
that only wanted a UID, and it is why the bridge does not use the wrapper.

## Counters, verification and RSA

**Counters saturate; they do not refuse.** A counter object is eight bytes —
four of value then four of threshold — both zero from the factory, which is why
the first `CTRINC` on a fresh counter answers `0x800E`. An increment that would
carry the value past the threshold **lands on the threshold and reports
success**: from 5 with a threshold of 10, `+99` gives 10 and OK. Only an
increment attempted at the threshold fails. `CTRINC` deliberately returns no
number — echoing the requested step would claim a move that did not happen — and
`TrustM.increment_counter()` reads the value back. Don't "fix" that by having
the firmware echo the step.

**Chip-side verification reports failure as a device error.** `0x802C` comes
back through the same status path as a malformed argument.
`TrustM.verify_on_chip()` turns `0x2C` into `False` and lets every other status
raise; `raw.verify()` keeps the exception.

**RSA is a SKU option and this silicon has it** — 1024 and 2048-bit, in
E0FC/E0FD. Its public key is a bare BIT STRING wrapping a **PKCS#1
RSAPublicKey**, not an EC point and not a SubjectPublicKeyInfo. Unlike ECDSA,
the RSA signature is complete as it stands — no missing SEQUENCE.

**Hashing past one line** uses the chip's own start/update/finalize.
`TrustM.hash()` switches to it above `maxdata`; `hash_file()` streams. The hash
context is the firmware's only cross-command state, and a failed update drops it
rather than letting a later finalize return a digest of the wrong thing.
`HASHUPD`/`HASHFIN` without a `HASHSTART` answer `E_STATE` (0xFF06).

## The wire protocol (protocol 2)

    [>] [tag] <CMD> [arg ...]            ->   < <tag> OK <CMD> [token ...]
                                              < <tag> ERR <CMD> <status> <stage>

The `>`, the space after it, and the tag are **all optional**, so `> 7 RAND 32`,
`>RAND 32` and `RAND 32` are one command. A tag is any leading token starting
with a digit; command names never do. An absent tag comes back as `-`.

The tag is a **correlation tag, not a sequence number** — it is opaque, never
parsed by the firmware, and answers only "which of my requests is this?". Don't
add arithmetic to it. It is optional for humans typing at a serial monitor and
**mandatory for anything driving the bridge in a loop**: without it, a reply to
a timed-out command is read as the answer to the next one, and every reply after
that is one command stale while still looking well-formed.

Replies echo the **canonical** command name, so `TRNG`/`DRNG` answer as `RAND`
and `?` as `HELP`; a host matching replies needs no alias table. The host checks
tag *and* command. An error hit before the command was identified echoes `-`,
which `transport.py` accepts for exactly that reason.

Any protocol change bumps `BRIDGE_PROTO` in the firmware and `PROTO_VERSION` in
`trustm/const.py`. `TrustM.ping()` raises on a mismatch; `python -m trustm ping`
passes `check=False` and reports it, because diagnosing an old board is what
ping is for.

`RDATA`/`WDATA` are capped at 1024 bytes per call by the bridge, reported as
`maxdata` in the `PING` reply so the host chunks to what the board says. Two
behaviours are worth knowing before changing anything there:

- **`RDATA`'s length is a ceiling, not a demand.** The chip returns what the
  object holds from the offset, so a short reply means the object ended. An
  object that is an exact multiple of the chunk size needs one more read, which
  answers device error 0x08; `read_data()` treats that as the end, not a fault.
- **`WDATA` has no OID guard, by design.** The firmware stays a complete
  mapping of the API. `TrustM.write_data()` is what refuses E0F0/E0E0 via
  `allow_provisioned=False`, so a guard belongs there and not in the sketch.

Safe objects to experiment on, from the factory metadata dump: **F1D0-F1DB**
(100 bytes each), **F1E0/F1E1** (1500 bytes — the ones large enough to exercise
chunking). `const.DATA_OBJECT_SIZES` lists them.
