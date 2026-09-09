# OPTIGA Trust M on a Trinkey RP2040

Driving an [Infineon OPTIGA Trust M](https://www.infineon.com/optiga-trust-m)
security chip from a desktop Python shell, through an Adafruit Trinkey RP2040 QT
acting as a bridge.

Part of [randomness](../README.md). The starting point was Adafruit's TRNG
gadget — the chip's hardware random number generator dumped over USB serial —
and the goal is to reach the rest of what the chip can do: its real random
number generator, its data objects, the certificate and key it left the factory
with, and signing with keys generated inside the chip.

```console
$ python -m trustm ping
trustm_bridge/0.6.0, protocol 2, OPTIGA host library 1.30.885, chip not yet opened

$ python -m trustm uid
CD16338401001C0001XXXXXXXXXXXXXXXXXXXXXXXX801010710809
  Trust M V1, firmware 1.30.809
  ...

$ python -m trustm rand 32
7EA367B784C696D9444EEDCD16AC09AFFC7C2F223CD06A617A6390A957F4737D

$ python -m trustm cert
0xE0E0  486 bytes, 1 certificate
  subject      CN=Infineon IoT Node
  issuer       CN=Infineon OPTIGA(TM) Trust M CA 101,OU=OPTIGA(TM),O=Infineon...
  public key   EC secp256r1 (256-bit)

$ python -m trustm keygen E0F1 --pem > key.pem      # key is made inside the chip
$ python -m trustm sign --file report.txt --raw > sig.der
$ openssl dgst -sha256 -verify key.pem -signature sig.der report.txt
Verified OK
```

## How it works

The Trust M is an I2C device, and a desktop has no I2C bus. Rather than tunnel
raw I2C over USB — which would add a round trip to every one of the transport
layer's polling loops and retries — the whole Infineon host library stays on the
RP2040, and the desktop drives it one command at a time over USB CDC:

```
  desktop                    USB CDC                  Trinkey RP2040
  ┌──────────────────┐                      ┌─────────────────────────┐
  │ trustm/          │   > 7 RAND 32 trng   │ trustm_bridge.ino       │      I2C
  │  the Python API  │ ───────────────────► │  parse, dispatch        │   ┌─────────┐
  │                  │ ◄─────────────────── │  Infineon host library  │◄─►│ Trust M │
  └──────────────────┘  < 7 OK RAND 9F2C... └─────────────────────────┘   └─────────┘
```

One command in, one OPTIGA operation, one reply out. The wire protocol is
line-oriented ASCII, and both the `>` and the tag are optional, so the whole
thing is drivable by hand from a serial monitor — `RAND 32` typed at the board
does what the line above does. Type `?` for the command list.

Two halves:

- **`firmware/trustm_bridge/`** — a command dispatcher for the RP2040. It calls
  the asynchronous `optiga_util_*` / `optiga_crypt_*` API directly rather than
  going through Infineon's Arduino C++ wrapper, which would discard the status
  codes, hardcode the TRNG, and write a platform binding secret just by
  starting up.
- **`trustm/`** — the host package: `transport.py` for framing, `raw.py` for
  one function per command, `device.py` for the `TrustM` class you actually use,
  plus a CLI at `python -m trustm`.

## What works

| command | description |
|---|---|
| `ping` | firmware version and limits, without touching the chip |
| `uid` | the 27-byte coprocessor UID, decoded into its fields |
| `rand` | random bytes, **TRNG by default**, DRNG on request, 64 if no length given |
| `read` | any data object, followed across as many calls as its size needs |
| `write` | any data object, in place or replacing it, with the factory-provisioned ones refused |
| `meta` | any object's metadata, decoded — sizes, lifecycle, access conditions |
| `cert` | the E0E0 device certificate, parsed, with chain verification |
| `keygen` | ECC keypairs, P-256 or P-384, in a slot, in the session, or exported |
| `sign` | ECDSA over a digest, verifiable by `openssl` on the desktop |
| `hash` | SHA-256 on the chip, streamed, so file size is no limit |
| `counter` | the four monotonic counters, read and incremented |
| `commands` | the command names this firmware answers to — the `HELP` command, so you can check for a feature instead of assuming it |

That is the whole build order. Also working, from the Python API: ECDH key
agreement (secrets match a desktop peer on both curves), chip-side ECDSA
verification, and **RSA** — which is a SKU option, so whether this silicon had
it was a question to answer rather than assume. It does: 1024- and 2048-bit
keys, signing PKCS#1 v1.5 that verifies with `cryptography`.

Still open: TLS-PRF key derivation, RSA encrypt/decrypt, protected updates, and
the shielded connection. See the [build order](bridge-plan.md#34-build-order).

Two things the chip returns are not the shape their names suggest — E0E0 is a
TLS-style container rather than a bare certificate, and a signature arrives
without its outer DER SEQUENCE. Both are handled, and both are written up in
[trustm.md](trustm.md#the-two-encodings-to-know-about), because each is an easy
hour to lose.

## Documentation

| | |
|---|---|
| [`build.md`](build.md) | getting from a clone to a board that answers: submodules, the patch, flashing, environment traps |
| [`trustm.md`](trustm.md) | using it: the command line, the Python API, data objects, the wire protocol, the architecture |
| [`bridge-plan.md`](bridge-plan.md) | why it is built this way — the design record, hardware inventory and build order |
| [`CLAUDE.md`](CLAUDE.md) | orientation for Claude Code sessions |

Infineon's own documentation is vendored under `subs/optiga-trust-m-overview`
rather than linked, so it is pinned and greppable offline: the Solution
Reference Manual as markdown, the Config Guide, Datasheet, Keys and
Certificates and I2C Protocol specification as PDFs, a factory metadata dump
from V1 silicon, and the root and intermediate CAs needed to verify the device
certificate chain.

## Getting started

```bash
git submodule update --init subs/arduino-optiga-trust-m subs/optiga-trust-m-overview
cd subs/arduino-optiga-trust-m
patch -p1 < ../../patches/0001-fix-pal-return-types.patch
ln -s $PWD ~/Arduino/libraries/OPTIGA_Trust_M
cd ../..

python -m trustm flash
python -m trustm ping
```

The library does not compile as published, hence the patch; **do not install it
through the Arduino IDE's Library Manager**, which replaces the symlink and
silently reverts the fix. Needs `arduino-cli` with the `rp2040:rp2040` core, and
`pyserial`. [`build.md`](build.md) has the detail.

## The chip

Both shields here are **Trust M V1, firmware 1.30.809**, which matters more than
anything else, because most of what is written about the Trust M describes V3.
V1 has TRNG and DRNG, SHA-256, ECC P-256/P-384, RSA 1024/2048 PKCS#1 v1.5, TLS
PRF SHA-256, data objects, metadata and monotonic counters. It has **no**
symmetric AES, HMAC or HKDF — those are V3 silicon, and no host library version
adds them.

Some chip state cannot be undone: E0F0 and E0E0 hold the factory-provisioned
Infineon attestation key and its certificate, the lifecycle state moves in one
direction only, and repeated failing operations trip a security monitor that
starts throttling the chip. [`trustm.md`](trustm.md#data-objects) says which
objects are safe to write.

## Layout

| path | what |
|---|---|
| `firmware/trustm_bridge/` | the bridge firmware |
| `trustm/` | the host package |
| `tools/gen_const.py` | regenerates `trustm/_generated.py` from the library headers |
| `trustm_boards/` | board identification: `identify.py`, the UID probe sketch, `boards.json` |
| `patches/` | the fix that makes the Arduino library compile |
| `subs/` | the Infineon library and documentation, as submodules |
| `reference/` | Arduino class reference |
| `archive/` | material this project no longer builds on — see [`archive/README.md`](archive/README.md) |

## Licences

The vendored Infineon libraries and the Adafruit TRNG gadget are MIT, and carry
their own licence headers. Everything written for this project is under whatever
[randomness](../README.md) is under.
