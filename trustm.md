# Using the bridge

How the Trinkey bridge is put together and how to drive it. For getting a board
built and flashed in the first place, see [`build.md`](build.md); for the
decisions behind all of this, [`bridge-plan.md`](bridge-plan.md).

- [Architecture](#architecture)
- [The command line](#the-command-line)
- [The Python API](#the-python-api)
- [Data objects](#data-objects)
- [The wire protocol](#the-wire-protocol)
- [Notes on the firmware](#notes-on-the-firmware)
- [The hardware](#the-hardware)

## Architecture

The Trust M is an I2C device. A desktop has no I2C bus, so the chip cannot be
reached from one directly — the usual answers are a USB-I2C adapter or a
Raspberry Pi. Here the Trinkey is already wired to the chip over STEMMA QT, so
the question is only where to cut the stack.

Infineon's host library is a tower:

```
  IFX_OPTIGA_TrustM        Arduino C++ wrapper - convenience, covers a slice
  optiga_util / _crypt     the real public API, asynchronous
  optiga_cmd               command and APDU construction
  optiga_comms_ifx_i2c     Infineon transport, optional shielded connection
  ifx_i2c_*_layer          presentation / transport / data link / physical
  pal_*                    platform abstraction - I2C, GPIO, timer
```

Cutting at the bottom — tunnelling raw I2C transactions over USB — is the
obvious idea and the wrong one. The physical layer does polling loops, guard
times and per-frame retries with real timing assumptions baked in, so every one
of them would gain a USB round trip. Cutting near the top instead means one
round trip per operation, and the timing-sensitive code stays where the timing
is. So the whole library runs on the RP2040, and the desktop sends it commands:

```
  desktop                    USB CDC                  Trinkey RP2040
  ┌──────────────────┐                      ┌─────────────────────────┐
  │ trustm/          │   > 7 RAND 32 trng   │ trustm_bridge.ino       │      I2C
  │  device.py       │ ───────────────────► │  parse, dispatch        │   ┌─────────┐
  │  raw.py          │                      │  optiga_crypt_random()  │◄─►│ Trust M │
  │  transport.py    │ ◄─────────────────── │  Infineon host library  │   └─────────┘
  └──────────────────┘   < 7 OK 9F2C...     └─────────────────────────┘
```

One command in, one OPTIGA operation, one reply out. The Infineon API is
asynchronous — register a callback, poll `optiga_lib_status` — and the firmware
absorbs all of that, so the host only ever sees request and response.

## The command line

```bash
python -m trustm ports              # list connected RP2040 boards
python -m trustm flash              # build and upload the bridge firmware
python -m trustm ping               # firmware version and limits
python -m trustm uid                # read and decode the coprocessor UID
python -m trustm rand 32            # 32 random bytes, as hex
python -m trustm read E0E0          # read a data object, as hex
python -m trustm write F1D0 DEADBEEF
```

Global options: `-p/--port` (default: the only RP2040 found), `-t/--timeout`
(default 5s), `-v/--verbose`.

`-v` is the thing to reach for when something is wrong; it shows both sides of
the conversation:

```console
$ python -m trustm -v read E0C5
> 1 PING
< 1 OK PING proto=2 fw=trustm_bridge/0.3.0 lib=1.30.885 maxline=4096 maxrand=256 maxdata=1024 open=1
> 2 RDATA E0C5 0 1024
< 2 OK 00
00
1 byte from 0xE0C5
```

The `PING` first is how `read` and `write` learn the board's chunk size. It
costs one round trip per process and does not touch the chip.

### rand

```bash
python -m trustm rand 32                        # TRNG, the default
python -m trustm rand 32 --source drng          # deterministic RNG instead
python -m trustm rand 1024 --raw > bytes.bin    # bytes, not hex
```

**The default source is the TRNG** — the chip's hardware entropy source. Pass
`--source drng` for the deterministic generator. GetRandom takes 8 to 256 bytes
per call; the host issues as many calls as the length needs, so `rand 1024` is
four calls and `rand 4` is one call for 8 bytes with 4 kept. Every byte handed
back came from the chip either way.

### read and write

```bash
python -m trustm read E0E0                      # whole object, as hex
python -m trustm read E0E0 --raw > cert.der     # bytes, not hex
python -m trustm read F1D0 --offset 4 --length 6
python -m trustm write F1D0 DEADBEEF            # replaces the object
python -m trustm write F1D0 FFFF --offset 2 --no-erase   # patch in place
python -m trustm write F1E0 --file payload.bin
```

The OID is hex (`E0E0`, or `0xE0E0`), or one of the library's own names —
`COPROCESSOR_UID`, `LCS_G`, `SECURITY_EVENT_COUNTER` and the rest of
`trustm.const.OIDS`.

`read` with no `--length` reads to the end of the object, following it across
as many calls as it takes. `write` replaces the object by default, so its
length becomes exactly what you wrote; `--no-erase` overwrites bytes at the
offset and leaves the rest alone.

`write` refuses E0F0 and E0E0 unless you pass `--allow-provisioned`. See
[Data objects](#data-objects).

### meta

```bash
python -m trustm meta E0E0        # one object
python -m trustm meta --all       # every object on the chip
python -m trustm meta F1D0 --raw  # the undecoded TLV
```

```
0xE0F1  byte_string  lcso=creation  alg=secp384r1  usage=sign  change=lcs_o < operational  execute=always
0xE0E0  device_cert  lcso=creation  size=486/1728  change=never  read=always  execute=always  LOCKED
0xE140  platform_binding  lcso=initialization  size=64/64  change=lcs_o < operational || conf(0xE140)  ...
```

**Reading metadata is always permitted**, including for objects whose contents
the access conditions refuse — so this is how you find out *why* a read failed,
rather than guessing from a `0x8007`. `--all` walks the 42 objects a V1 chip
has, which is the factory dump taken from your own silicon.

`LOCKED` means the object can never be changed again: either its change
condition is `never`, or it is gated on a lifecycle state the object has already
passed. Lifecycle only moves forward, so such a gate can never reopen.

Writing metadata goes through `TrustM.write_metadata()`, which merges — writing
one tag leaves the others alone — and refuses three permanent changes unless
told otherwise: advancing `lcso`, setting any access condition to `NEV`, and
touching E0F0 or E0E0. The chip enforces none of that; it will lock an object
out of existence without asking.

### cert

```bash
python -m trustm cert                    # parse and describe E0E0
python -m trustm cert --verify           # follow the chain to a root
python -m trustm cert --pem > device.pem
python -m trustm cert --der | openssl x509 -inform der -noout -text
python -m trustm cert E0E1               # the empty slots
```

E0E0 holds Infineon's device certificate, signed at the factory over the
attestation key in E0F0. That pairing is the chip's identity: anything that can
sign with E0F0 is this chip, and the certificate is the part you can show
someone.

**`--verify` will not complete on these boards, and that is not a bug.** Both
certificates are issued by *Infineon OPTIGA(TM) Trust M CA 101*, and the CAs
that come with `subs/optiga-trust-m-overview` are CA 300, CA 306, CA 309 and a
test CA. The certificate carries no authorityInfoAccess either, so there is no
URL in it to follow. Put CA 101 in a directory and pass `--ca-dir` and the chain
completes. The verifier is known good — it completes the three bundled CA chains
to their roots and rejects a deliberately mismatched issuer.

### keygen and sign

```bash
python -m trustm keygen                        # P-256 signing key into E0F1
python -m trustm keygen E0F2 --curve p384 --usage sign+auth
python -m trustm keygen session                # volatile, gone at the next reset
python -m trustm keygen export                 # private key handed back
python -m trustm keygen E0F1 --pem > key.pem

python -m trustm sign --file report.txt --raw > sig.der
python -m trustm sign 9F2C... --slot E0F2 --curve p384
openssl dgst -sha256 -verify key.pem -signature sig.der report.txt
```

That last pair is the whole point: the private key is generated inside the chip
and never leaves it, and an independent tool confirms the signature.

`export` and a slot are mutually exclusive — see [the wire
protocol](#the-wire-protocol). A `session` key lives in the chip's volatile
session context and is gone at the next reset, which makes it the safe place to
experiment.

`keygen` refuses E0F0 unless you pass `--allow-provisioned`: it holds the
attestation key that E0E0's certificate attests to, and overwriting it destroys
that binding permanently.

## The Python API

```python
from trustm import TrustM

with TrustM() as tm:
    print(tm.ping())                    # trustm_bridge/0.2.0, protocol 1, ...
    print(tm.uid())                     # Trust M V1, firmware 1.30.809
    print(tm.uid().hex)                 # 27 bytes, unique to the chip
    print(tm.random(32).hex())          # TRNG by default
    print(tm.random(32, source="drng").hex())

    cert = tm.read_data(0xE0E0)         # the whole object, chunked as needed
    tm.write_data(0xF1D0, b"scratch")   # replaces the object
    tm.write_data(0xF1D0, b"\xff\xff", offset=2, erase=False)   # patch in place
```

The port is found automatically when exactly one RP2040 is connected; pass
`TrustM(port="/dev/ttyACM0")` otherwise.

### Three layers

Each one has a single job:

| module | what it does |
|---|---|
| `transport.py` | framing, sequence numbers, timeouts, resync. Knows nothing about the chip. |
| `raw.py` | one function per command, bytes in and bytes out. The chip's limits are its limits. |
| `device.py` | the `TrustM` class. Parses replies into objects and works around per-call limits. |

`raw.rand(t, 4)` fails, because the chip's GetRandom takes 8 to 256 bytes;
`tm.random(4)` succeeds, because it asks for 8 and keeps 4. Likewise
`raw.rdata` is one read of at most 1024 bytes, while `tm.read_data` follows an
object of any size across as many reads as it takes. That split is deliberate —
`raw.py` stays a readable inventory of what the chip actually does, and the
conveniences are somewhere you can see them.

### Errors

Errors carry the real status code rather than a boolean:

```python
>>> tm.read_data(0xFFFF)
trustm.errors.DeviceError: RDATA read: 0x8001 OPTIGA_DEVICE_ERROR (0x01 invalid OID)
```

`TrustMError` is the root:

```
TrustMError
  TransportError        the serial link itself
    PortNotFound        no board matched, or more than one did
    Timeout             no reply within the deadline
    ProtocolError       a reply arrived but did not parse
  CommandError          the firmware replied ERR
    BridgeError         0xFFxx - the firmware refused the command
    OptigaError         a host-library status code
      DeviceError       0x8xxx - the chip itself refused
```

`DeviceError.device_code` is the low byte, decoded against the reference
manual's error table. Two account for most of what goes wrong while exploring:
`0x07` (access conditions not satisfied) and `0x01` (invalid OID). `0x08` (data
object boundary exceeded) is the third, and is not always a fault — reading is
how you discover an object's size, so `read_data` treats it as the end of the
object rather than an error.

### Metadata

```python
with TrustM() as tm:
    m = tm.metadata(0xF1D0)
    print(m)                       # the one-line summary above
    print(m.object_type, m.max_size, m.used_size, m.lifecycle)
    print(m.access("change"))      # 'lcs_o < operational'
    print(m.locked)                # can this ever be changed again?

    for oid, m in tm.objects().items():
        print(f"{oid:04X} {m}")

    # merges: the other tags are left alone
    tm.write_metadata(0xF1D0, {"read": bytes.fromhex("e1fc07")})
```

`Metadata.fields` holds every tag's raw value in the order the chip sent them,
so `metadata.build(m.fields)` reproduces the original bytes exactly and an
unrecognised tag is never silently dropped.

### Hashing, agreement, counters and RSA

```bash
python -m trustm hash --file report.txt --check   # chip vs host SHA-256
python -m trustm counter E120 --set 100           # value 0, threshold 100
python -m trustm counter E120 --increment --step 5
```

```python
with TrustM() as tm:
    tm.hash(b"data")                    # any length; streams past one line
    tm.hash_file("big.bin")             # never held in memory

    # ECDH against a desktop peer
    peer = ec.generate_private_key(ec.SECP256R1())
    shared = tm.key_agreement(peer.public_key(), slot=0xE0F1)

    # the chip checking a signature, rather than the host
    tm.verify_on_chip(pair, signature, digest)     # a bool, not an exception

    value, threshold = tm.increment_counter(0xE120, 5)

    rsa = tm.generate_rsa_keypair(0xE0FC, bits=2048)
    sig = tm.rsa_sign(digest, slot=0xE0FC)
    keys.rsa_verify(rsa.public, sig, digest)
```

### Certificates and keys

```python
from trustm import TrustM
import hashlib

with TrustM() as tm:
    cert = tm.certificate()                 # parsed X.509 from E0E0
    print(cert.subject.rfc4514_string())

    pair = tm.generate_keypair(0xE0F1, curve="p256", usage="sign")
    print(pair)                             # p256 sign key, slot 0xE0F1
    print(pair.public_key)                  # a cryptography public key
    print(pair.point.hex())                 # 0x04 || X || Y

    digest = hashlib.sha256(b"hello").digest()
    signature = tm.sign(digest, slot=0xE0F1)        # complete DER
    assert tm.verify(pair.public, signature, digest)
```

`KeyPair.public` and `.private` are the chip's own encodings, kept so nothing is
lost; `.public_key` and `.private_key` are usable objects. `.private` is None
unless the key was exported, and asking for `.private_key` then says so rather
than returning nothing.

## Data objects

The chip's storage is a set of numbered objects, each with its own size and
access conditions. The ground truth for this chip is the factory metadata dump
at `subs/optiga-trust-m-overview/data/object_dumps/trust_m1_json.txt`.

**Safe to experiment with:**

| OID | size | what |
|---|---|---|
| `F1D0`–`F1DB` | 100 bytes each | twelve general-purpose objects. `F1D0` is the conventional scratchpad. |
| `F1E0`, `F1E1` | 1500 bytes | large general-purpose objects — big enough to exercise chunking |
| `E0E1`–`E0E3` | 1728 bytes | spare certificate slots |
| `E0E8`, `E0E9`, `E0EF` | 1200 bytes | trust anchors and similar |

**Read-only status objects**, useful and impossible to damage:

| OID | what |
|---|---|
| `E0C0` / `F1C0` | lifecycle state, global and application |
| `E0C1` / `F1C1` | security status |
| `E0C2` | coprocessor UID, 27 bytes |
| `E0C5` | security event counter — read this when the chip inexplicably slows down |
| `F1C2` | error codes |

**Do not write these:**

| OID | what |
|---|---|
| `E0F0` | the Infineon attestation private key |
| `E0E0` | the certificate that matches it |

`E0E0` is worth a note: the object is 484 bytes but the certificate inside it
is 475, because Infineon prefixes a 9-byte length header. `openssl x509 -inform
der` skips it without complaint, so the shell one-liner works as written;
Python's `cryptography` does not, and wants `raw[9:]`.

Overwriting either destroys the chip's factory identity for good. `write_data`
refuses both unless passed `allow_provisioned=True`; the chip's own metadata
also marks them `change: never`, but that is a second line of defence rather
than the first. Use `E0F1` for key experiments.

Two other things are one-way and worth knowing before you find out:

- **Lifecycle state never goes backwards.** `LCS_G` (E0C0) and `LCS_A` (F1C0)
  run creation → initialization → operational → termination. `E0F1`–`E0F3`
  become immutable once the state passes `operational`.
- **The security monitor throttles the chip** after repeated failing
  operations, counted in `E0C5`. If everything suddenly gets slow, read it
  before assuming anything else.

## The wire protocol

Line-oriented ASCII. The `>` and `<` are literal, not notation:

```
[>] [tag] <CMD> [arg ...]\n           host to device
< <tag> OK <CMD> [token ...]\n        device to host
< <tag> ERR <CMD> <status> <stage>\n  device to host
# <free text>\n                       unsolicited note, ignore
```

Hex doubles the payload size, and in exchange the whole thing is drivable by
hand from a serial monitor and framing bugs — the classic time sink in a bridge
like this — simply do not exist.

### The tag

It is a **correlation tag, not a sequence number**. The host picks it, the board
echoes it back verbatim without ever parsing it, and it answers exactly one
question: *which of my requests is this?*

The failure it prevents: the host sends `RAND`, the chip is slow, the host times
out and sends `UID`. The `RAND` reply then arrives and, with nothing to match
on, is read as the answer to `UID`. Every reply after that is one command stale,
each one individually well-formed — which is why it is miserable to debug.
Matching on the tag discards the straggler and the stream resynchronises.

The tag is also what makes `E_OVERFLOW` answerable: it is the first token, so it
usually survives a truncated line and the error can be attributed to the right
request.

### What is optional, and for whom

Both the `>` prefix and the tag can be left out. These are all the same command:

```
> 7 RAND 32          >RAND 32          RAND 32
```

A tag is any leading token starting with a digit; command names never do, so the
two can never be confused. When no tag is given the reply carries `-` in its
place, which keeps every reply the same shape rather than making each consumer
sniff for a missing field.

**The tag is optional for humans and mandatory for programs.** Typing `RAND 32`
at a serial monitor and reading the answer with your eyes needs no correlation.
Anything driving the bridge in a loop does, and the resulting desync is invisible
until something retries. `SerialTransport` always sends a tag and the `>`.

### The echoed command

Replies name the command they answer. It is a second, independent check — the
host matches on tag *and* command — and it makes a raw capture readable without
scrolling back to find the request.

It does not replace the tag, because command names are not unique across
retries: two `RAND 32` calls in a row are indistinguishable by name, which is
precisely the case the tag exists for.

The name echoed is the **canonical** one, so `TRNG` and `DRNG` answer as `RAND`
and `?` answers as `HELP`. A host matching replies against what it sent needs no
table of aliases. An error the firmware hit before it could identify a command —
an overflowed line, a tag with nothing after it — echoes `-`.

`MAX_LINE` is 4096 on both sides and both assert it; the firmware answers
`E_OVERFLOW` and keeps consuming to the newline rather than truncating a
command in half. The ceiling comes from `OPTIGA_MAX_COMMS_BUFFER_SIZE` (1557
bytes), which hex-encodes to about 3.1 KB.

### Commands

| | |
|---|---|
| `PING` | protocol, firmware and library version, limits, whether the chip is open |
| `UID` | coprocessor UID, OID 0xE0C2, 27 bytes |
| `RAND [len] [trng\|drng]` | 8 to 256 random bytes. 64 and `trng` if omitted. |
| `TRNG [len]`, `DRNG [len]` | `RAND` with the source fixed; length only |
| `RDATA <oid> [offset] [len]` | read a data object, up to 1024 bytes per call |
| `WDATA <oid> <offset> <hex> [write\|erase]` | write a data object, up to 1024 bytes per call |
| `RMETA <oid>` | read an object's metadata |
| `WMETA <oid> <hex>` | write metadata; merges, and some changes are one-way |
| `KEYGEN <slot\|session\|export> [curve] [usage]` | generate an ECC keypair |
| `SIGN <slot\|session> <digest-hex>` | ECDSA over a digest |
| `VERIFY <curve> <pubkey> <digest> <sig>` | ECDSA verified by the chip |
| `HASH <hex>` | SHA-256 on the chip, up to 1024 bytes |
| `HASHSTART`, `HASHUPD <hex>`, `HASHFIN` | streaming SHA-256, any length |
| `ECDH <slot\|session> <curve> <peer-pub>` | key agreement, secret exported |
| `CTRINC <oid> [step]` | bump a monotonic counter |
| `RSAGEN <slot> <1024\|2048> [usage]` | RSA keypair — this silicon has RSA |
| `RSASIGN <slot> <digest> [sha256\|sha384]` | RSA PKCS#1 v1.5 signature |
| `HELP`, `?` | the syntax and the command list |

`RAND`'s two arguments are independently optional, and a length is recognised by
starting with a digit rather than by its position — so `RAND drng` means 64
bytes from the DRNG, not a malformed length. They must still come in order;
`RAND drng 16` is `E_ARGS`.

`TRNG` and `DRNG` take a length and nothing else. A source argument after one of
them either repeats or contradicts the command name, and `E_ARGS` is a better
answer than guessing which wins. So `RAND`, `RAND 64`, `RAND trng`,
`RAND 64 trng` and `TRNG` are five spellings of one command.

`HELP` prints its prose as `#` notes, which every host already ignores, and puts
just the command names on the `OK` line. That makes it a feature check as well as
documentation — `TrustM.commands()` returns the set, so a host can ask whether a
board has `RDATA` rather than assuming.

`PING` deliberately does not touch the chip. It answers from firmware constants
alone, so it stays a usable "is the bridge alive and what does it speak" check
even with the shield missing or dead:

```
> 1 PING
< 1 OK PING proto=2 fw=trustm_bridge/0.3.0 lib=1.30.885 maxline=4096 maxrand=256 maxdata=1024 open=1
```

`UID` is then the first command that touches the chip, which makes it the check
that the shield is attached and working. The application is opened lazily on the
first such command and stays open until the board resets, which is what `open=`
reports.

`RDATA`'s `len` is a ceiling, not a demand: the chip returns however much the
object actually holds from `offset`, which is how a certificate of unknown size
gets read in one go. `WDATA`'s `erase` is `OPTIGA_UTIL_ERASE_AND_WRITE` — the
object is discarded first, so its length becomes exactly what was written —
against `write`, which is `OPTIGA_UTIL_WRITE_ONLY` and leaves the rest of the
object alone. It answers with the number of bytes written.

`KEYGEN` takes `export` in the slot position rather than as a trailing flag,
because the two are mutually exclusive: `export_private_key = TRUE` turns the
API's `private_key` argument from an OID into a buffer, so a key is either kept
in the chip or handed to the host, never both. `curve` is `p256` or `p384`;
`usage` is `sign`, `auth`, `agree` or `encrypt`, joined with `+`. Defaults are
`E0F1 p256 sign`.

`SIGN` signs the digest exactly as given — the chip does no hashing. A 32-byte
digest suits P-256 and 48 bytes P-384, though the chip will in fact sign a
shorter one without complaint.

### Status codes

A status is an `optiga_lib_status_t` when the failure came from the library, or
`0x8000 | code` when the chip itself refused. Codes of the form `0xFFxx` — a
range `optiga_lib_status_t` never uses — mean the firmware refused the command
before it reached the chip:

| code | | |
|---|---|---|
| `0xFF01` | `E_CMD` | unknown command |
| `0xFF02` | `E_ARGS` | wrong argument count or unparseable argument |
| `0xFF03` | `E_RANGE` | argument outside the allowed range |
| `0xFF04` | `E_OVERFLOW` | line longer than `MAX_LINE` |
| `0xFF05` | `E_TIMEOUT` | chip did not complete in time |
| `0xFF06` | `E_STATE` | `HASHUPD` or `HASHFIN` with no `HASHSTART` |

### The two encodings to know about

Neither `KEYGEN` nor `SIGN` returns what a general-purpose library expects, and
both fail a long way from the cause. `trustm/keys.py` handles both; this is what
it is handling.

**The public key is a bare DER BIT STRING**, not a SubjectPublicKeyInfo:

```
03 42 00 04 <X 32 bytes> <Y 32 bytes>       P-256, 68 bytes
^  ^  ^  ^
|  |  |  uncompressed-point marker
|  |  unused bits
|  length
BIT STRING
```

There is no AlgorithmIdentifier, so nothing in the encoding says which curve it
is — the caller has to remember what it asked for, which is why
`keys.public_key()` takes the curve as an argument. `cryptography` will not load
it as a public key; the point inside it loads fine.

**The signature has no outer SEQUENCE.** The chip emits the two INTEGERs for r
and s and stops:

```
02 21 00DFC0…  02 20 7F3ADB…               69 bytes for P-256
```

A complete DER signature wraps those in `30 <len>`. Without it every verifier
rejects the signature, which looks like a bad signature rather than a framing
problem — so it is worth knowing before you go hunting in the key.
`keys.der_signature()` adds the wrapper and is idempotent, and `TrustM.sign()`
returns the wrapped form. `raw.sign()` returns the chip's bytes untouched.

**An exported private key** is a DER OCTET STRING around the raw scalar,
`04 20 <32 bytes>` for P-256. `optiga_crypt_ecc_generate_keypair` never says how
many bytes it wrote there — the Arduino wrapper accepts a `prlen` and does not
pass it on — so the firmware sizes the buffer for the largest key the chip can
produce and recovers the length from the DER.

### Counters, and the trap in them

A counter object is eight bytes — a four-byte value then a four-byte threshold —
and both are zero from the factory. That is why the first `CTRINC` on a fresh
counter answers `0x800E`: the value is already at the threshold. Write both with
`WDATA` (or `TrustM.set_counter()`) first.

**An increment that would carry the value past the threshold saturates at the
threshold and reports success.** From 5 with a threshold of 10, `+99` leaves the
counter at 10 and returns OK. Only an increment attempted *at* the threshold
fails. `CTRINC` therefore returns no number — echoing the requested step would
claim a move the counter did not make — and `TrustM.increment_counter()` reads
the value back and returns where it actually landed.

"Monotonic" describes the counter, not the object: while the object's change
access condition is open, `WDATA` resets it. It is one-way only once locked.

### RSA on this silicon

RSA is an OPTIGA SKU option, and the host library being built with it says
nothing about the chip on the other end of the bus. **These boards have it** —
1024 and 2048-bit keys in E0FC/E0FD, signing PKCS#1 v1.5 that verifies with
`cryptography`.

The public key has the same shape problem as the ECC one: a bare DER BIT STRING
with no AlgorithmIdentifier, wrapping a **PKCS#1 RSAPublicKey** rather than an
EC point. `keys.rsa_public_key()` unwraps it. Unlike ECDSA, the RSA signature is
complete as it stands.

### Verification on the chip

`VERIFY` has the chip check a signature instead of the host. It reports a bad
one as device error `0x802C`, through the same status path as a malformed
argument — right on the wire, wrong for a caller, so
`TrustM.verify_on_chip()` turns `0x2C` into `False` and lets everything else
keep raising.

It is not a substitute for verifying on the desktop. It is useful when the
verifying party *is* the chip — checking a peer's signature before acting on it.

### Still to come

Protocol changes bump `proto=`, and `TrustM.ping()` raises unless the board
matches `const.PROTO_VERSION`. `python -m trustm ping` deliberately does not —
reporting what is actually on the board is the whole point of `ping` when it
turns out to be running something old.

`TLS_PRF_SHA256` key derivation, RSA encrypt/decrypt, protected updates
(`SetObjectProtected`), and the shielded connection — which needs a platform
binding secret and would make bridge debugging harder. See
[`bridge-plan.md`](bridge-plan.md) §3.2 for the intended full set and §3.4 for
the order.

## Notes on the firmware

`firmware/trustm_bridge/trustm_bridge.ino` deliberately does **not** use the
`IFX_OPTIGA_TrustM` C++ wrapper, even though the wrapper is the obvious thing to
reach for. Three reasons:

- The wrapper collapses every failure to `1`, discarding the status code that
  makes an error diagnosable.
- It hardcodes TRNG, so `RAND ... drng` would be impossible.
- Its `begin()` runs `pairMCU()` by default, which writes a platform binding
  secret. Calling `optiga_util_*` / `optiga_crypt_*` directly skips that, so the
  bridge never modifies the chip just by starting up.

The library's own `OPTIGA_ASSERT_WAIT_WHILE_BUSY` macro spins forever if the
chip stops answering, so the firmware pumps the asynchronous callback against a
deadline and reports `E_TIMEOUT` instead. A wedged bridge is much worse than an
error.

There is no OID guard in the firmware. It stays a complete mapping of the API,
and refusing the factory-provisioned objects is `TrustM.write_data()`'s job —
which does mean that driving `WDATA` by hand from a serial monitor can destroy
the chip's identity with no one to stop you.

## The hardware

A Trinkey RP2040 QT (FQBN `rp2040:rp2040:adafruit_trinkeyrp2040qt`) and
two Trust M Shield2Go boards. The shields get swapped between hosts, so nothing
here treats a pairing as fixed — see
[`build.md`](build.md#identifying-which-board-is-which).

### What this chip can do

Both shields are **Trust M V1, firmware 1.30.809**. This matters more than
anything else here, because most of what is written about the Trust M describes
V3:

| | |
|---|---|
| Random | TRNG, DRNG |
| Hash | SHA-256 only |
| ECC | NIST P-256, P-384 — keygen, ECDSA, ECDH |
| RSA | 1024 / 2048, PKCS#1 v1.5 only |
| KDF | TLS PRF SHA-256 |
| Objects | certificates, arbitrary data objects, metadata, monotonic counters |

**Not on V1:** symmetric AES, HMAC, HKDF, `generate_auth_code`. Those are V3
*silicon* features, and no host library version adds them. The `testAES128CCM*`
functions in the Arduino wrapper are mbedTLS running on the RP2040, not the chip.
