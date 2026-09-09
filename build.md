# Building and flashing

Everything needed to get from a fresh clone to a board that answers `PING`.
For what to do with it afterwards, see [`trustm.md`](trustm.md).

## What you need

| | |
|---|---|
| Hardware | An Adafruit Trinkey RP2040 QT, and an OPTIGA Trust M Shield2Go on its STEMMA QT connector |
| Firmware build | `arduino-cli` with the `rp2040:rp2040` core |
| Host | Python 3 with `pyserial` |

No soldering: the shield connects to the Trinkey with a STEMMA QT cable.

Versions this was built and tested against: arduino-cli 1.5.1, rp2040 core
6.1.0, pyserial 3.5, Infineon host library 1.30.885.

## The Arduino library needs a patch

The Infineon Arduino library does not compile as published. Six `pal_status_t`
functions fall off the end without returning a value, which the rp2040 core
rejects under `-Werror=return-type`, and one string literal trips
`-Wwrite-strings`.

The library therefore lives here as a submodule, patched in place, and the
Arduino IDE is pointed at it by symlink — so what the IDE builds is what is
version-controlled:

```bash
git submodule update --init subs/arduino-optiga-trust-m
cd subs/arduino-optiga-trust-m
patch -p1 < ../../patches/0001-fix-pal-return-types.patch
ln -s $PWD ~/Arduino/libraries/OPTIGA_Trust_M
```

Afterwards `git -C subs/arduino-optiga-trust-m diff --stat` should show exactly
three files. That dirty submodule is the expected state, not a mistake.

> **Do not install or update OPTIGA Trust M through the Arduino IDE's Library
> Manager.** It replaces the symlink with a fresh copy and silently reverts the
> patch, and the build then fails somewhere that looks unrelated.

Any `git submodule update` that resets the submodule drops the patch too.
Re-apply it with the same `patch -p1` line.

The vendored documentation is worth fetching as well — it is what makes the
reference manual greppable offline:

```bash
git submodule update --init subs/optiga-trust-m-overview
```

## Build and flash

```bash
python -m trustm ports          # confirm the board is there
python -m trustm flash          # build firmware/trustm_bridge and upload it
python -m trustm ping           # should answer with a version
```

`flash` shells out to `arduino-cli`, so the hand-run equivalent is:

```bash
arduino-cli compile --fqbn rp2040:rp2040:adafruit_trinkeyrp2040qt \
  --libraries ~/Arduino/libraries --build-path firmware/.build \
  firmware/trustm_bridge
arduino-cli upload --fqbn rp2040:rp2040:adafruit_trinkeyrp2040qt \
  -p /dev/ttyACM0 --input-dir firmware/.build firmware/trustm_bridge
```

**If the board goes silent after a flash, upload a second time before
concluding anything is broken.** An upload can report success while the board
carries on running its previous firmware; an identical second upload takes
effect. This has happened more than once and looks exactly like a hardware
fault.

## Regenerating the constants

Host and firmware have to agree on OIDs, RNG types and status codes.
Transcribing them by hand is how the two drift apart, so `trustm/_generated.py`
is parsed out of the headers the firmware is compiled against:

```bash
./tools/gen_const.py            # rewrite trustm/_generated.py
./tools/gen_const.py --check    # exit 1 if it is stale
```

Run it after any change to the Arduino library. Do not hand-edit
`_generated.py`. Constants that exist in no C header — the chip's own error
table, the bridge protocol's own codes — are hand-written in `trustm/const.py`,
which re-exports the generated module.

## Identifying which board is which

A shield is not bound to a particular Trinkey — they get swapped around — so
`trustm_boards/identify.py` keeps an inventory keyed on the chip's coprocessor
UID, recording the Trinkey it was last seen on rather than assuming a fixed
pairing. It writes `trustm_boards/boards.json`, which is gitignored because a
coprocessor UID and a USB serial number are unique hardware identifiers;
`boards.example.json` shows the shape.

```bash
cd trustm_boards
./identify.py --label "spare"     # read the UID and record the board
./identify.py --list              # show what is recorded
./identify.py --samples 5         # require more agreeing reads (default 3)
./identify.py --no-flash          # never write to the board
./identify.py --flash             # force a reflash first
```

Shields bought together are likely to be siblings from a single wafer lot. Two
here differ in **two of their 27 UID bytes** — the batch-number tail and wafer
Y — so a swapped shield reads almost exactly like a corrupted read of the other
one. That caused a real mix-up once, which is why `identify.py` insists on
several consecutive agreeing reads before it will record anything.

It predates the bridge and drives its own probe sketch,
`trustm_boards/uid_probe/`, which prints the UID on a repeating loop. (The
stock `getUniqueID` example prints once and halts, which races USB
re-enumeration after a flash — you get a board that appears to say nothing.)

**The two flashing paths overwrite each other**, because a board holds one
sketch. `identify.py` only reflashes when its first read fails, but that is
exactly what happens when the bridge firmware is loaded, so running it against
a bridge board will replace the bridge with the probe. `python -m trustm flash`
puts the bridge back.

## Environment traps

All of these have bitten already.

**Arduino IDE 2 is a Flatpak** (`cc.arduino.IDE2`) and cannot upload to an
RP2040 without:

```bash
flatpak override --user --filesystem=/run/media cc.arduino.IDE2
```

The core's `uf2conv.py` calls `udisksctl`, which is absent from the Flatpak
runtime; the override makes its `/run/media` fallback scan work instead. The
`Exception executing udisksctl` line still prints and is cosmetic. Because the
fallback depends on GNOME automount, it fails with the screen locked.
`arduino-cli` from a terminal is less exposed, but **not immune**: its uploader
is the same core `uf2conv.py`, so when the bootloader drive does not automount
it fails the same way, with `Scanning for RP2040 devices / No drive to deploy`.

**A serial monitor holding `/dev/ttyACM0` causes exactly that message.** The
1200-baud touch cannot reset a port another process has open, so the board never
enters the bootloader and the uploader finds no drive. `fuser -v /dev/ttyACM0`
names the holder — VS Code's `serial-monitor` helper is the usual one. Close it
and upload again. The message says nothing about the port being busy, so this
looks like a flashing or hardware fault rather than what it is.

**USB IDs are not consistent between boards.** One Trinkey here enumerates as
`239a:8109` and `arduino-cli` names it correctly; the other comes up as
`2e8a:8109` ("PicoArduino") from what should be an identical build, which
defeats `arduino-cli`'s vid+pid match. The cause is not established. Don't rely
on `arduino-cli board list` naming the model — the host package accepts either
vendor ID, and so does `identify.py`.

**Shielded connection stays off.** `optiga_lib_config.h` defaults to
`OPTIGA_COMMS_NO_PROTECTION` and should stay there: enabling it needs a
platform binding secret written into E140, and it only makes bridge debugging
harder.

## Watching the serial line directly

The wire protocol is plain ASCII precisely so that this works:

```bash
python3 -c "
import serial
ser = serial.Serial('/dev/ttyACM0', 115200, timeout=1)
ser.write(b'> 1 PING\n')
print(ser.readline().decode().strip())"
```

Any serial monitor will do the same. The firmware ignores every line that does
not begin with `> `, so a half-typed command cannot desynchronise anything.
