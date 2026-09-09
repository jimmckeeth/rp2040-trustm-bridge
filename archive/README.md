# Archive

Material this project no longer builds on. Nothing here is broken or wrong —
it is kept because it is where the project started, or because it is the route
to take if the goal ever changes. Nothing outside this directory refers to it.

## `adafruit/`

The original TRNG gadget, which is what started this. A Trinkey and a Trust M
shield emitting the chip's hardware random numbers over USB serial:
`trinkey_rp2040_trust_m_trng.ino` in raw, CSV or JSON format selected by
`TRNG_FORMAT`, with matching `read-raw.py` / `read-csv.py` / `read-json.py`
host readers and prebuilt UF2s. Also the Trinkey datasheet and Adafruit's guide
for the gadget.

Superseded by the bridge, which reaches the same generator through
`python -m trustm rand` along with the rest of the chip — but the sketch is
still the simplest possible demonstration of the hardware, and the UF2s flash
without a toolchain.

## `subs/`

Four Infineon repositories, kept as submodules.

| | |
|---|---|
| `linux-optiga-trust-m` | Linux command-line tools and examples |
| `optiga-trust-m-openssl` | OpenSSL 3.x provider |
| `pkcs11-optiga-trust-m` | PKCS#11 module |
| `optiga-trust-m` | the upstream host library, for non-Arduino targets |

The first three all assume a real `/dev/i2c-N`, so they cannot be reached
through a Trinkey at all. They would need a USB-I2C adapter (MCP2221A, FT260)
or a Raspberry Pi with the shield on its own I2C bus. That is the path to take
if the chip is ever wanted as a working key store rather than an exploration
target, which is why they are kept rather than dropped.

`optiga-trust-m` is the same host library that the Arduino port wraps, laid out
for other build systems. `subs/arduino-optiga-trust-m` carries the same
`optiga_util` / `optiga_crypt` sources and is the copy the firmware is actually
compiled against, so this one is a second opinion rather than a dependency.

The documentation lives in `subs/optiga-trust-m-overview`, which is **not**
archived — the Solution Reference Manual, the factory metadata dump and the
Infineon CA certificates are all in daily use.

## Getting them back

They are still submodules, just at a different path, so nothing special is
needed:

```bash
git submodule update --init archive/subs/linux-optiga-trust-m
```

Their entries in `.gitmodules` keep their original names, which is what `git
mv` does to a submodule; the `path` is what matters and it points here.
