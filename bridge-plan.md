# OPTIGA Trust M — Trinkey bridge plan

Exploring the Trust M's feature set from a desktop Python library, with the
Infineon host library staying on the microcontroller and the desktop talking to
it over USB CDC.

Written 2026-09-03. Self-contained: everything established so far is recorded
here, so this folder can be moved anywhere.

---

## 1. Hardware

An **Adafruit Trinkey RP2040 QT** (FQBN
`rp2040:rp2040:adafruit_trinkeyrp2040qt`) and an **OPTIGA Trust M Shield2Go**.
A shield is not bound to a particular Trinkey — they get swapped around, so
treat the pairing as "last seen on", never as an identity.

Everything here was developed against **Trust M V1, firmware 1.30.809**.

A coprocessor UID looks like this, with the fields that are identical across
every Trust M V1 kept and the ones that identify a particular chip zeroed:

| | |
|---|---|
| Coprocessor UID | `CD16338401001C0001` `XXXXXXXXXXXXXXXX` `XX` `XX` `801010710809` |
| batch number | 8 bytes, unique to the wafer lot |
| wafer X / Y | 1 byte each, unique to the die |

`trustm_boards/identify.py` records the real values in
`trustm_boards/boards.json`, keyed on the OPTIGA UID because the shield is the
thing being identified. **That file is gitignored** — a coprocessor UID and an
RP2040 USB serial are unique hardware identifiers, and there is no reason to
publish them. `trustm_boards/boards.example.json` shows its shape.

### UID layout (OID 0xE0C2, 27 bytes)

```
CD           CIM identifier
16           Platform identifier
33           Model identifier
84 01        ROM mask ID
00 1C 00 01 00 00        chip type
0A 09 1B 5C 00 0B 00 3x  batch number
00 / 9x      wafer X / Y
80 10 10 71  firmware identifier
08 09        build number   ->  FW 1.30.809
```

The header, ROM mask, chip type, batch number, firmware identifier and build
number follow Infineon's documented layout. The single-byte split of wafer X and
Y is inferred from the byte budget — every other field is fixed-width and the
total must reach 27. It does not affect revision detection, which reads the
build number.

### Revision detection

Firmware identifier `0x80101071` appears on **both** revisions; the **build
number** is the discriminator:

| build | revision | firmware |
|---|---|---|
| `08 09` | Trust M V1 | 1.30.809 |
| `24 40` | Trust M V3 | 3.00.2440 |

---

## 2. What Trust M V1 can actually do

Taken from the enums in the installed library
(`~/Arduino/libraries/OPTIGA_Trust_M/src/optiga_trustm/optiga_lib_common.h`),
not from marketing material.

| | |
|---|---|
| Random | TRNG, DRNG |
| Hash | SHA-256 only |
| ECC | NIST P-256, P-384 — keygen, ECDSA sign/verify, ECDH |
| RSA | 1024 / 2048, PKCS#1 v1.5 only (sign SHA-256/384, encrypt/decrypt) |
| KDF | TLS PRF SHA-256 |
| Key slots | E0F0–E0F3 (ECC), E0FC / E0FD (RSA), session-based |
| Key usage | authentication, sign, key agreement, encryption |
| Objects | IFX device cert E0E0, project slots E0E1–E0E3, arbitrary data objects |
| Other | metadata r/w, monotonic counters, protected update, shielded connection |

**Not available on V1:** symmetric AES, HMAC, HKDF, `generate_auth_code`. Those
are V3 *silicon* features. Upgrading the host library past the bundled
v1.30.885 gains newer API headers and no new chip capability — the bundled
version already matches this silicon's firmware (1.30.885 vs FW 1.30.809).

### Useful OIDs

```
E0C0  lifecycle state, global      E0E0  IFX device cert (provisioned)
E0C1  security status, global      E0E1  project cert slot 1
E0C2  coprocessor UID              E0E2  project cert slot 2
E0C3  sleep mode activation delay  E0E3  project cert slot 3
E0C4  current limitation           E0F0  device privkey 1 (provisioned)
E0C5  security event counter       E0F1  device privkey 2
F1C0  lifecycle state, app         E0F2  device privkey 3
F1C1  security status, app         E0F3  device privkey 4
F1C2  error codes                  E0FC  RSA privkey 1
                                   E0FD  RSA privkey 2
```

---

## 3. Bridge plan

Two halves: a command-dispatcher firmware, and a host package. The design goal
is that the Python API is the thing you think in, and the firmware stays a dumb,
complete mapping of the Infineon API.

### 3.1 Wire protocol  — implemented, protocol 2

Line-oriented ASCII. The `>` and `<` are literal, not notation:

```
[>] [tag] <CMD> <arg> ...\n              host to device
< <tag> OK <CMD> [token ...]\n           device to host
< <tag> ERR <CMD> <status_hex> <stage>\n device to host
# <free text>\n                          unsolicited note, ignore
```

Most commands answer with one hex token; `PING` answers with `key=value`
tokens; `HELP` answers with command names and puts its prose in `#` notes.

Hex-encoding doubles payload size and that is the right trade: the whole thing
is drivable by hand from a serial monitor, and framing bugs — the classic time
sink in a bridge like this — simply do not exist.

The chip's buffer caps a transfer at `OPTIGA_MAX_COMMS_BUFFER_SIZE` = 1557
bytes, so worst-case lines are ~3.1 KB. `MAX_LINE = 4096` on both sides, and
both assert it — the firmware answers `E_OVERFLOW` and keeps consuming to the
newline rather than truncating into a half command.

#### The tag

**It is a correlation tag, not a sequence number.** Protocol 1 called it `seq`,
which was wrong: nothing about it is sequential to the device, which never
parses it and echoes it back as an opaque string. It answers one question —
which of my requests is this? — so that after a timeout or a board reset, a
reply to an abandoned command is discarded instead of being read as the answer
to the next one. Every reply in that failure mode is individually well-formed
and every answer is one command stale, which is miserable to debug later.

Treating it as opaque removed code at both ends: the firmware no longer does
`strtoul` on it, and the host no longer has an "unparseable sequence number"
path. A host may use a counter, a UUID fragment, anything starting with a digit
and at most `TAG_MAX` (32) characters.

A device-generated counter was considered and rejected: it answers a different
question (did I miss a reply?), and here a lost reply already presents as a
timeout and a board reset already shows as `open=0` on the next `PING`. Cheap
to add later if it earns its place.

#### What is optional

The `>`, the whitespace after it, and the tag are all optional, so `> 7 RAND
32`, `>RAND 32` and `RAND 32` are one command. A tag is any leading token
starting with a digit; command names never do, which is what keeps them apart.
An absent tag comes back as `-`, so replies stay fixed-shape rather than making
every consumer sniff for a missing field.

This is a deliberate asymmetry: **optional for humans, mandatory for programs.**
Hand-typing at a serial monitor needs no correlation; anything driving the
bridge in a loop does, and skipping it produces a desync that stays invisible
until something retries. `SerialTransport` always sends both.

Dropping the required `>` costs one thing: a garbage line now draws an `E_CMD`
reply instead of being silently ignored. That is harmless — its tag is `-`, so
it never matches a real request — and arguably better at a serial monitor,
where silence and a rejected command look identical.

#### The echoed command

Replies name the command they answer, and the host matches on tag **and**
command. It is a second, independent check and it makes a raw capture readable
without scrolling back to find the request.

It does not replace the tag: command names are not unique across retries, so two
`RAND 32` calls in a row cannot be told apart by name — the exact case the tag
exists for. On the error path this was already half-present as `<stage>`; only
success replies were anonymous.

The name echoed is canonical, so `TRNG`/`DRNG` answer as `RAND` and `?` as
`HELP`, and a host needs no alias table. An error hit before a command could be
identified echoes `-`.

Protocol changes bump `proto=` in `PING`. `TrustM.ping()` raises on a mismatch;
`python -m trustm ping` reports it instead, since a board running the wrong
firmware is exactly what `ping` is for.

`<status_hex>` is an `optiga_lib_status_t` where the failure came from the
library or the chip (`0x8000 | code` is the chip's own, decoded against the SRM
error table), and `0xFFxx` where the firmware itself refused the command —
a range `optiga_lib_status_t` never uses:

| code | | |
|---|---|---|
| `0xFF01` | `E_CMD` | unknown command |
| `0xFF02` | `E_ARGS` | wrong argument count or unparseable argument |
| `0xFF03` | `E_RANGE` | argument outside the allowed range |
| `0xFF04` | `E_OVERFLOW` | line longer than `MAX_LINE` |
| `0xFF05` | `E_TIMEOUT` | chip did not complete in time |
| `0xFF06` | `E_STATE` | command needs state the bridge does not have (`HASHUPD` before `HASHSTART`) |

`E_TIMEOUT` exists because the library's own `OPTIGA_ASSERT_WAIT_WHILE_BUSY`
spins forever if the chip stops answering. A wedged bridge is much worse than
an error, so the firmware pumps the async callback with a deadline instead.

If throughput ever matters, swap to COBS + CRC behind the same `Transport`
interface. It will not matter for exploration.

**One command = one OPTIGA operation.** The Infineon API is asynchronous
(register a callback, poll `optiga_lib_status`); the firmware absorbs that
entirely and the host only ever sees request/response. Use the `trustM.*` C++
wrapper where it covers the operation and drop to `optiga_util_*` /
`optiga_crypt_*` where it does not — the wrapper only surfaces a slice.

### 3.2 Command set

Implemented: **`PING`, `UID`, `RAND`, `RDATA`, `WDATA`, `RMETA`, `WMETA`,
`KEYGEN`, `SIGN`, `VERIFY`, `HASH`, `HASHSTART`/`HASHUPD`/`HASHFIN`, `ECDH`,
`CTRINC`, `RSAGEN`, `RSASIGN`, `HELP`** — the whole build order.

`KEYGEN` takes `export` in the slot position rather than as a trailing flag,
which is a deliberate departure from the sketch above. They are mutually
exclusive in the API: `export_private_key = TRUE` turns the `private_key`
argument from an OID into a buffer, so a key is either kept in the chip or
handed to the host, never both.

```
PING                                      proto, fw and lib version, limits
UID
HELP / ?                                  -> command names, prose in # notes
RAND    [len] [trng|drng]                 -> both optional; default 64, trng
TRNG    [len]   /   DRNG [len]            -> RAND with the source fixed
RDATA   <oid> [offset] [len]              -> hex, up to 1024 bytes per call
WDATA   <oid> <offset> <hex> [write|erase] -> bytes written
KEYGEN  <slot|session|export> [curve] [usage]  -> pubkey [privkey]
SIGN    <slot|session> <digest-hex>       -> r,s with no SEQUENCE
RMETA   <oid>                             -> the metadata TLV
WMETA   <oid> <hex>                       -> bytes written; merges, one-way
VERIFY  <curve> <pubkey> <digest> <sig>   -> chip-side ECDSA; 0x802C = bad
HASH    <hex>                             -> SHA-256, up to 1024 bytes
HASHSTART / HASHUPD <hex> / HASHFIN       -> streaming SHA-256
ECDH    <slot|session> <curve> <peer-pub> -> shared secret, exported
CTRINC  <oid> [step]                      -> no count; it saturates
RSAGEN  <slot> <1024|2048> [usage]        -> PKCS#1 pubkey in a BIT STRING
RSASIGN <slot> <digest> [sha256|sha384]   -> PKCS#1 v1.5, complete
VERIFY  <pubkey-hex> <digest-hex> <sig-hex>
ECDH    <slot> <peer-pub-hex> [export]
HASH    <hex>
RSAGEN / RSASIGN / RSAENC / RSADEC
COUNTER <oid> <step>
LIMIT   <ma>
```

`RDATA` takes offset/len from day one so large objects chunk naturally. That
paid off immediately: `len` turns out to be a ceiling rather than a demand — the
chip returns however much the object holds from `offset` — so an object of
unknown size is read by asking for the maximum and watching for a short reply.
An object that is an exact multiple of the chunk size needs one further read,
which comes back as device error 0x08 (boundary exceeded); `TrustM.read_data()`
treats that as the end of the object rather than a fault.

`WDATA`'s mode is explicit rather than inferred from the offset.
`erase` is `OPTIGA_UTIL_ERASE_AND_WRITE`, which discards the object first so its
length becomes exactly what was written; `write` is `OPTIGA_UTIL_WRITE_ONLY`,
which overwrites in place and leaves the rest. The firmware defaults to the
smaller action, `write`; `TrustM.write_data()` defaults to `erase`, because
"write this object" normally means replace it, and a short `WRITE_ONLY` at
offset 0 leaving a stale tail is a trap. A chunked write erases only on the
first chunk.

Both are capped at 1024 bytes per call. `OPTIGA_MAX_COMMS_BUFFER_SIZE` (1557)
and `MAX_LINE` (4096, halved by hex) are the two ceilings above it; 1024 clears
both with room for the reply's own tokens, and `PING` reports it as `maxdata`
so the host chunks to whatever the board says rather than to a hardcoded
number.

There is deliberately **no OID guard in the firmware** — it stays a complete
mapping of the API, and `TrustM.write_data()` is what refuses E0F0 and E0E0
(`allow_provisioned=False`). The cost is that `WDATA` driven by hand from a
serial monitor can destroy the chip's identity with nothing to stop it.

`PING` deliberately does not touch the chip — it answers from firmware
constants alone, so it stays a usable "is the bridge alive and what does it
speak" check even with the shield missing or dead:

```
> 1 PING
< 1 OK proto=1 fw=trustm_bridge/0.1.0 lib=1.30.885 maxline=4096 maxrand=256 open=1
```

`UID` is then the first command that touches the chip, which makes it the
check that the shield is attached and working. The application is opened
lazily on the first such command and stays open until the board resets, so
`open=` tells you whether that has happened yet.

`RAND` is capped at 8–256 bytes by the chip (SRM 4.4.1.6 GetRandom). The
firmware enforces that rather than papering over it; `TrustM.random()` on the
host chunks anything larger and, below 8, asks for the minimum and keeps what
was wanted.

The firmware does **not** use the `IFX_OPTIGA_TrustM` C++ wrapper. The wrapper
collapses every failure to `1`, discarding the status code that makes an error
diagnosable, and it hardcodes TRNG so `RAND ... drng` would be impossible.
Calling `optiga_util_*` / `optiga_crypt_*` directly also skips the wrapper's
`begin()` default of `pairMCU()`, so the bridge never writes a platform
binding secret.

### 3.3 Python package layout

```
firmware/trustm_bridge/
  trustm_bridge.ino   the command dispatcher
trustm/
  transport.py   SerialTransport — framing, seq, timeout, reconnect
  errors.py      exception hierarchy over the status codes
  const.py       hand-maintained constants; re-exports _generated
  _generated.py  OIDs, RNG types, status codes — do not edit
  raw.py         1:1 command wrappers, bytes in / bytes out
  device.py      TrustM — the API you actually use
  cli.py         python -m trustm ports | flash | ping | uid | rand 32
tools/
  gen_const.py   parses the C headers -> trustm/_generated.py
```

`gen_const.py` was worth writing on day one rather than hand-transcribing
constants — it stops host and firmware drifting as commands are added. It reads
the headers in `subs/arduino-optiga-trust-m`, i.e. the exact library the
firmware is compiled against, and `--check` fails if the generated file is
stale. Only what has no C header is hand-written in `const.py`: the chip's own
error codes, which live only in the SRM, and the bridge protocol constants that
have to match the sketch.

Make `device.py` return real objects, not bytes:
`tm.generate_keypair(slot=0xE0F1, curve="P-256")` hands back a `cryptography`
`EllipticCurvePublicKey`, `tm.certificate(0xE0E0)` an `x509.Certificate`,
`tm.sign(slot, data)` a DER signature. That interop is the whole payoff of
being on the desktop — verifying a chip-made signature against a chip-made
public key in three lines of `cryptography` is the fastest possible proof that
the bridge is correct end to end.

### 3.4 Build order

1. ~~`PING` + `UID`, plus `transport.py`. Proves framing.~~ **Done.**
2. ~~`RAND`, `RDATA` / `WDATA` into a scratch data object. No key state — safe
   to hammer.~~ **Done.** `RAND` on both TRNG and DRNG; `RDATA` / `WDATA`
   verified against F1D0 (100 bytes) and F1E0 (1500 bytes, so the chunking is
   exercised on real hardware), and `RDATA` reads the E0E0 certificate whole.
3. ~~Read and parse the E0E0 IFX device certificate. First real payoff, and it
   exercises chunked reads.~~ **Done.** `trustm/cert.py` parses the container
   (see below), `TrustM.certificate()` returns the parsed certificate and
   `python -m trustm cert --verify` follows the chain. **The chain cannot be
   completed offline:** both boards' certificates are issued by *Infineon
   OPTIGA(TM) Trust M CA 101*, and the submodule ships CA 300, CA 306, CA 309
   and a test CA, but not CA 101. The certificate carries no
   authorityInfoAccess, so there is no URL in it to follow either. The verifier
   is known good - it completes CA 300, CA 306 and CA 309 to their roots, and
   rejects a deliberately mismatched issuer.
4. ~~`KEYGEN` + `SIGN`, verified on the desktop.~~ **Done.** Both curves, all
   four key usages, persistent slots, session keys and exported keys.
   End-to-end: `keygen --pem` then `sign --file`, verified by `openssl dgst
   -verify` as an independent check, with a tampered-file negative control.

#### What E0E0 actually holds

Not a certificate. A TLS-style container with three nested lengths in front of
the DER:

```
C0 <u16>        tag, then the length of everything after these three bytes
   <u24>        length of the certificate list
   <u24> <DER>  one certificate, repeated
```

486 bytes on one board here, holding a 477-byte certificate — the size varies
between chips, which is why nothing assumes it. `openssl x509 -inform
der` appears to work on the raw object because it reads the first DER structure
and ignores the nine bytes in front; `cryptography` refuses. Both are correct,
which makes this an easy hour to lose.

#### The two encodings KEYGEN and SIGN return

Neither is what a general-purpose library expects, and both fail far from the
cause:

- **The public key is a bare DER BIT STRING**, `03 42 00 04 || X || Y` for
  P-256 — no AlgorithmIdentifier, so nothing in it says which curve it is. It
  will not load as a public key; the point inside loads with
  `from_encoded_point`, and the curve has to be remembered from the request.
- **The signature has no outer SEQUENCE.** The chip emits the two INTEGERs for
  r and s and stops. Every verifier rejects that, and it reads like a bad
  signature rather than a framing problem. `keys.der_signature()` wraps it.
- An exported private key is a DER OCTET STRING around the raw scalar.

`optiga_crypt_ecc_generate_keypair` also never reports how many bytes it wrote
into the exported-private-key buffer - the Arduino wrapper takes a `prlen` and
does not pass it on. The firmware sizes the buffer for the largest key the chip
can make and recovers the length by parsing the DER.
5. ~~Metadata reads. Then, and only then, metadata writes.~~ **Done.** `RMETA`
   and `WMETA`, with `trustm/metadata.py` decoding the TLV against the SRM's
   tables. `python -m trustm meta --all` surveys all 42 objects on the chip -
   the equivalent of the factory dump, taken from your own silicon.

#### What metadata is for

Metadata is a constructed TLV under tag 0x20, and **reading it is always
permitted** - including for objects whose *contents* the access conditions
refuse. That makes `RMETA` the way to find out why a read failed, rather than
guessing from a 0x8007.

The decoder is validated against the 41-object V1 factory dump in
`subs/optiga-trust-m-overview`: 240 of 241 checks agree with Infineon's own
`pretty_metadata`, and the one difference is a list rendered as a string. Every
object on the real chip also round-trips exactly through `build(parse(x))`.

#### Writes, and what is not reversible

`WMETA` merges rather than replaces - writing one tag leaves the others alone,
verified by writing `read` alone and getting back byte-identical metadata after
restoring it. Three things it can do cannot be undone, so `TrustM.write_metadata()`
refuses each unless told otherwise:

- **`lcso`** advances the object's lifecycle, which only ever moves forward.
  E0F1-E0F3 carry `change: lcso < operational`, so advancing theirs to
  operational makes them permanently immutable.
- **an access condition of NEV** locks that operation out for good.
- **E0F0 and E0E0**, whose metadata is part of the factory identity.

The chip enforces none of this. It will lock an object out of existence without
asking, which is why the guard is at the device layer and the firmware stays a
complete mapping.

6. ~~Monotonic counters, `ECDH`, `HASH`, the RSA operations.~~ **Done.**
   `HASH` (one-shot and streaming), `VERIFY`, `ECDH`, `CTRINC`, `RSAGEN` and
   `RSASIGN`. ECDH secrets match a desktop peer on both curves; RSA signatures
   verify with `cryptography`; the chip's SHA-256 matches `sha256sum` on a real
   file.

#### RSA is present on this silicon

RSA is an OPTIGA SKU option and the host library being built with it says
nothing about the chip on the other end of the I2C bus - so this was a question
to answer rather than assume. **These boards have it.** RSAGEN produces 1024-
and 2048-bit keys in E0FC/E0FD and RSASIGN produces PKCS#1 v1.5 signatures that
verify on the desktop.

The public key has the same shape problem as the ECC one: a bare DER BIT STRING
with no AlgorithmIdentifier, wrapping a **PKCS#1 RSAPublicKey** rather than an
EC point. `keys.rsa_public_key()` unwraps it. Unlike ECDSA, the RSA signature is
complete as it stands - no missing SEQUENCE.

#### Counters saturate rather than refusing

A counter object is eight bytes: a four-byte value then a four-byte threshold.
Both are zero from the factory, which is why the very first `CTRINC` answers
`0x800E` - the counter is already at its threshold. Write both with `WDATA`
first.

**An increment that would carry the value past the threshold saturates at the
threshold and reports success.** From 5 with a threshold of 10, `+99` leaves the
counter at 10 and returns OK. Only an increment attempted when the value is
already at the threshold fails. `CTRINC` therefore returns no number at all -
echoing the requested step would claim a move the counter did not make - and
`TrustM.increment_counter()` reads the value back and returns where it actually
landed.

"Monotonic" describes the counter, not the object: while the object's change
access condition is open, `WDATA` resets it. It is one-way only once locked.

#### Verification failure is a device error

`optiga_crypt_ecdsa_verify` reports a bad signature as `0x802C`, through the
same status path as a malformed argument. That is right on the wire and wrong
for a caller, so `TrustM.verify_on_chip()` turns `0x2C` back into `False` and
lets every other status keep raising.

#### Hashing past one line

`HASH` carries up to `DATA_LEN_MAX` bytes, which hex-encodes to half of
`MAX_LINE`. The chip's API is start/update/finalize, so `HASHSTART` /
`HASHUPD` / `HASHFIN` expose that and `TrustM.hash()` switches to it above the
limit; `hash_file()` streams a file without reading it into memory. The context
is the firmware's only piece of cross-command state, and a failed update drops
it rather than letting a later finalize return a digest of the wrong thing.

7. Still open: `TLS_PRF_SHA256` key derivation, RSA encrypt/decrypt, protected
   updates (`SetObjectProtected`), and the shielded connection - which needs a
   platform binding secret and would make bridge debugging harder.

### 3.5 Guard rails to build in, not bolt on

- **E0F0 and E0E0 are factory-provisioned** — the Infineon attestation key and
  its matching certificate. Overwriting E0F0 destroys that identity
  permanently. Use E0F1 for experiments, and put an `allow_provisioned=False`
  keyword on any write path touching those OIDs.
- **Lifecycle state is one-way.** `LCS_G` (E0C0) and `LCS_A` (F1C0) go
  creation -> initialization -> operational -> termination and never back. Do
  not expose a termination path without an explicit confirmation argument.
- **The security monitor will bite.** Repeated failing operations increment the
  security event counter (E0C5) and the chip starts throttling. Expose
  `tm.security_event_counter()` early — otherwise an afternoon disappears
  wondering why everything got slow.
- **Leave shielded connection off.** `optiga_lib_config.h` already defaults to
  `OPTIGA_COMMS_NO_PROTECTION`. Enabling it needs a platform binding secret in
  E140 and only makes bridge debugging harder.

---

## 4. Environment notes

Things that cost time to work out, worth not rediscovering.

**Arduino IDE 2 is a Flatpak** (`cc.arduino.IDE2`) and cannot upload to RP2040
out of the box. The rp2040 core's `uf2conv.py` shells out to `udisksctl`, which
is not in the Flatpak runtime, and its fallback scan of `/run/media` failed
because the sandbox only had `filesystems=home`. Fixed with:

```
flatpak override --user --filesystem=/run/media cc.arduino.IDE2
flatpak override --user --filesystem=/media cc.arduino.IDE2
```

The `Exception executing udisksctl` line still prints on every upload and is
cosmetic — the mount now comes from GNOME's automount instead. This depends on
automount, so it will not work with the screen locked; uploading via
`arduino-cli` from a host terminal has no such dependency.

**The library needed patching to compile** under `-Werror=return-type`. Six
`pal_status_t` functions in `pal_logger_arduino.cpp` and `pal_gpio_arduino.cpp`
fell off the end without a return. `pal_logger_read` is an unimplemented stub
and now returns `PAL_STATUS_FAILURE`; the rest return `PAL_STATUS_SUCCESS`.
`output_result` in `OPTIGATrustM.cpp` took `char*` for a string literal and now
takes `const char*`.

They are captured in `patches/0001-fix-pal-return-types.patch`. Upstream
`arduino-optiga-trust-m` master is otherwise byte-identical to the released
v1.1.0, so the patch applies cleanly to a pristine checkout.

The library is now a submodule at `subs/arduino-optiga-trust-m` with that patch
applied, and `~/Arduino/libraries/OPTIGA_Trust_M` is a symlink to it — so what
the IDE builds is what is in this repo. The submodule is permanently dirty
against upstream by design; `git -C subs/arduino-optiga-trust-m diff` should
show exactly those three files. To rebuild the relationship from scratch:

    git submodule update --init subs/arduino-optiga-trust-m
    cd subs/arduino-optiga-trust-m
    patch -p1 < ../../patches/0001-fix-pal-return-types.patch
    ln -s $PWD ~/Arduino/libraries/OPTIGA_Trust_M

`~/Arduino/libraries/OPTIGA_Trust_M.bak` is the original Library Manager copy,
kept as a fallback.

**USB IDs are not consistent between boards.** The core declares the Trinkey as
`239a:8109`. One Trinkey running this probe enumerates that way and
`arduino-cli` identifies it correctly; the other enumerated as `2e8a:8109`
(`PicoArduino`) from what should have been an identical build, which stops
`arduino-cli`'s vid+pid match from identifying the model. The cause is not
established. `identify.py` accepts either VID and falls back to an assumed
FQBN, so it works both ways — but do not rely on `arduino-cli board list`
naming the model.

**Uploads can race USB re-enumeration.** An upload reported success but the
board came back running the previous firmware; an identical second upload took
effect. If a freshly flashed board is silent, re-flash before concluding
anything is broken. (The uploader also writes the UF2 twice, to `/run/media`
and `/var/run/media` — the same directory via Fedora's symlink. Harmless.)

**The probe sketch pairs the MCU, and it shows.** `uid_probe` calls
`trustM.begin()`, and the wrapper declares `begin(uint8_t pairDevice = 1)` — so
pairing is the *default*, and `pairMCU()` writes a platform binding secret into
On a board that had run the probe this is visible in the metadata: E140 is
`lcso=initialization` where the factory dump has `creation`. No permanent harm — E140's change
condition is `lcso < operational`, so it is still writable — but it is a real
write to a security object performed by a sketch that only wanted to read a UID.
The bridge firmware calls `optiga_util_*` directly and never runs `pairMCU()`,
which is one of the reasons it does not use the wrapper.

**Never trust a single UID read.** Shields bought together are likely wafer-lot
siblings; two here differ in only two of 27 bytes — the batch-number tail and wafer Y. A
swapped shield looks almost exactly like a corrupted read of the other one.
This caused a real mix-up on 2026-09-03. `identify.py` now requires three
consecutive agreeing reads (`--samples`).

---

## 5. Files

| path | what |
|---|---|
| `README.md` | what the project is, in summary |
| `trustm.md` | using it: command line, Python API, data objects, wire protocol |
| `build.md` | building and flashing, and the environment traps |
| `firmware/trustm_bridge/` | the bridge firmware — `PING`, `UID`, `RAND`, `RDATA`, `WDATA`, `RMETA`, `WMETA`, `KEYGEN`, `SIGN`, `HELP` |
| `trustm/` | the host package |
| `tools/gen_const.py` | regenerates `trustm/_generated.py` from the library headers |
| `trustm_boards/identify.py` | detects the board, reads and decodes the UID, upserts `boards.json` |
| `trustm_boards/uid_probe/` | probe sketch — prints the UID on a repeating loop |
| `trustm_boards/boards.json` | board inventory, keyed on OPTIGA UID |
| `patches/` | fixes to the Arduino library, applied to the submodule |
| `subs/` | Infineon repos as submodules, including the patched Arduino library |
| `reference/` | Arduino class reference HTML |
| `archive/` | the original Adafruit TRNG gadget, and the Infineon repos that need a real `/dev/i2c-N` |

### Using the bridge

Needs `pyserial`, and `arduino-cli` for the `flash` step.

```
python -m trustm ports          # what is connected
python -m trustm flash          # build and upload the bridge firmware
python -m trustm ping           # firmware version and limits
python -m trustm uid            # read and decode the coprocessor UID
python -m trustm rand 32        # 32 random bytes as hex
python -m trustm rand 1024 --source drng --raw > bytes.bin
python -m trustm read E0E0      # read a data object as hex
python -m trustm write F1D0 DEADBEEF
python -m trustm -v uid         # also print the wire traffic to stderr
```

```python
from trustm import TrustM

with TrustM() as tm:
    print(tm.ping())            # trustm_bridge/0.2.0, protocol 1, ...
    print(tm.uid())             # Trust M V1, firmware 1.30.809
    print(tm.uid().hex)
    print(tm.random(32).hex())
    cert = tm.read_data(0xE0E0)
    tm.write_data(0xF1D0, b"scratch")
```

`flash` overwrites whatever sketch is on the board — including `uid_probe`, so
run `trustm_boards/identify.py` before switching a board over if you still need
it to record a UID. (The bridge's own `uid` command reads the same OID, but
`identify.py` is the thing that insists on several agreeing reads.)

### The probe sketch and the bridge

`uid_probe` predates the bridge and still exists because `identify.py` drives
it. It prints on a loop rather than once — the stock `getUniqueID` example
prints once and halts, which races USB re-enumeration after a flash. The
bridge answers on demand instead, so it has no such race.

```
./identify.py                    # read UID, flashing the probe only if needed
./identify.py --label "spare"    # attach a name
./identify.py --list             # show what is recorded
./identify.py --samples 5        # require more agreeing reads
./identify.py --no-flash         # never write to the board
```

`identify.py` assumes the Arduino library lives at `~/Arduino/libraries`; that
path is hardcoded in `flash()` and needs changing if the library moves.

---

## 6. Documentation already in this repo

Prefer these over the web — they are pinned as submodules.

| what | where |
|---|---|
| Solution Reference Manual v3.70 (**greppable markdown**, covers the V1/V3 split) | `subs/optiga-trust-m-overview/docs/OPTIGA™ Trust M Solution Reference Manual.md` |
| Same, plus Config Guide, Datasheet, Keys & Certificates, I2C Protocol v2.03 | `subs/optiga-trust-m-overview/docs/pdf/` |
| **Factory object/metadata dump from V1 silicon** — ground truth for build step 5 | `subs/optiga-trust-m-overview/data/object_dumps/trust_m1_json.txt` |
| **Infineon root and intermediate CAs** — needed to verify the E0E0 chain in build step 3 | `subs/optiga-trust-m-overview/data/certificates/` |

The M1 dump is worth reading before touching metadata. It shows E0F0 as
`change: never` — the chip itself refuses to overwrite the provisioned key — and
E0F1–E0F3 as `change: lcso < operational`, meaning they become immutable once
the lifecycle state is advanced.

## 7. References

- [Infineon/optiga-trust-m](https://github.com/Infineon/optiga-trust-m) — current host library
- [Infineon/optiga-trust-m-overview](https://github.com/Infineon/optiga-trust-m-overview) — product family, PAL porting
- [Infineon/linux-optiga-trust-m](https://github.com/Infineon/linux-optiga-trust-m) — Linux tools, V1/V3
- [Infineon/optiga-trust-m-openssl](https://github.com/Infineon/optiga-trust-m-openssl) — OpenSSL 3.x provider
- [Infineon/pkcs11-optiga-trust-m](https://github.com/Infineon/pkcs11-optiga-trust-m) — PKCS#11 module
- [Arduino library API reference](https://infineon.github.io/arduino-optiga-trust-m/df/d1c/class_i_f_x___o_p_t_i_g_a___trust_m.html)

The last three assume a real `/dev/i2c-N` and are the path to take if the
desktop ever needs the chip as a working key store rather than an exploration
target — that needs a USB-I2C bridge (MCP2221A, FT260) or a Raspberry Pi, not
the Trinkey.
