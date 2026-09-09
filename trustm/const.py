"""
Constants for the Trust M bridge.

Most of this is re-exported from _generated.py, which tools/gen_const.py parses
out of the Infineon headers the firmware is compiled against. Only the things
that have no C header - the chip's own error codes and the bridge protocol
itself - are written by hand here.
"""

from ._generated import (  # noqa: F401
    ECC_CURVES,
    KEY_IDS,
    KEY_USAGES,
    LIB_VERSION,
    OIDS,
    RETURN_CODE_ALIASES,
    RETURN_CODES,
    RNG_TYPES,
    SESSION_OIDS,
)

#: Protocol version this package speaks; PING reports the firmware's.
#: 2 made the tag opaque and optional and added the echoed command to replies,
#: so a proto-1 board and this package cannot understand each other's replies.
PROTO_VERSION = 2

#: Both sides assert this. Worst case is a 1557-byte payload hex-encoded.
MAX_LINE = 4096

#: GetRandom accepts 0x0008-0x0100 bytes per call (SRM 4.4.1.6 GetRandom).
#: TrustM.random() chunks and pads around these; raw.rand() does not.
RAND_LEN_MIN = 8
RAND_LEN_MAX = 256

#: What RAND returns when no length is given. Firmware and host agree on it so
#: that a bare `RAND` typed at a serial monitor and raw.rand() with no length
#: mean the same thing.
RAND_LEN_DEFAULT = 64

#: Largest RDATA/WDATA payload the firmware will frame in one line. PING
#: reports the board's own figure as `maxdata`; this is the default used before
#: anyone has asked. TrustM.read_data()/write_data() chunk around it.
DATA_LEN_MAX = 1024

#: OPTIGA_MAX_COMMS_BUFFER_SIZE in optiga_lib_config.h - the ceiling on any
#: single transfer to or from the chip.
MAX_COMMS_BUFFER = 1557

#: Coprocessor UID (OID 0xE0C2) is 27 bytes.
UID_LENGTH = 27

# Bridge-level failures reported by the firmware, in a range optiga_lib_status_t
# never uses. Keep in step with firmware/trustm_bridge/trustm_bridge.ino.
BRIDGE_ERRORS = {
    0xFF01: ("E_CMD", "unknown command"),
    0xFF02: ("E_ARGS", "wrong argument count or unparseable argument"),
    0xFF03: ("E_RANGE", "argument outside the allowed range"),
    0xFF04: ("E_OVERFLOW", "command line longer than MAX_LINE"),
    0xFF05: ("E_TIMEOUT", "chip did not complete the operation in time"),
    0xFF06: ("E_STATE", "command needs state the bridge does not have"),
}

#: Status codes at or above this are the chip's own, with the low byte holding
#: the code from the SRM table below (OPTIGA_DEVICE_ERROR).
DEVICE_ERROR_BASE = 0x8000

# From the Solution Reference Manual, table "Error Codes" (section 4.3). These
# exist in no C header, so unlike everything above they are transcribed.
# Source: subs/optiga-trust-m-overview/docs/OPTIGA(tm) Trust M Solution
# Reference Manual.md
DEVICE_ERRORS = {
    0x00: "no error",
    0x01: "invalid OID",
    0x03: "invalid Param field in command",
    0x04: "invalid Length field in command",
    0x05: "invalid parameter in command data field",
    0x06: "internal process error",
    0x07: "access conditions not satisfied",
    0x08: "data object boundary exceeded (offset + length > object size)",
    0x09: "metadata truncation error",
    0x0A: "invalid command field",
    0x0B: "command or message out of sequence",
    0x0C: "command not available (application closed, or terminated state)",
    0x0D: "insufficient buffer or memory to process the command",
    0x0E: "counter threshold limit exceeded",
    0x0F: "invalid manifest",
    0x10: "invalid or wrong payload version",
    0x11: "invalid metadata of the key or data object",
    0x24: "unsupported extension or identifier",
    0x25: "unsupported parameters",
    0x29: "invalid certificate format",
    0x2A: "unsupported certificate",
    0x2C: "signature verification failure",
    0x2D: "integrity validation failure",
    0x2E: "decryption failure",
    0x2F: "authorization failure",
}

# Coprocessor UID layout, 27 bytes. The header, chip type, batch number,
# firmware identifier and build number are per the SRM; the single-byte wafer
# X/Y split is inferred from the byte budget - every other field is fixed-width
# and the total must come to 27. Mirrors trustm_boards/identify.py.
UID_FIELDS = (
    ("cim_identifier", 0, 1),
    ("platform_identifier", 1, 2),
    ("model_identifier", 2, 3),
    ("rom_mask_id", 3, 5),
    ("chip_type", 5, 11),
    ("batch_number", 11, 19),
    ("wafer_x", 19, 20),
    ("wafer_y", 20, 21),
    ("firmware_identifier", 21, 25),
    ("build_number", 25, 27),
)

# The firmware identifier (0x80101071) is the same on both revisions; the build
# number is the discriminator. Its bytes read as decimal digits, not as a
# number: 0x08 0x09 is build 809, not 2057.
BUILD_TO_REVISION = {
    "0809": ("V1", "1.30.809"),
    "2440": ("V3", "3.00.2440"),
}

# --------------------------------------------------------------- data objects

#: Write modes the firmware accepts for WDATA. `write` is
#: OPTIGA_UTIL_WRITE_ONLY, which overwrites bytes at the offset and leaves the
#: rest of the object; `erase` is OPTIGA_UTIL_ERASE_AND_WRITE, which discards
#: the object first so its length becomes exactly what was written.
WRITE_MODES = ("write", "erase")

#: Objects the chip leaves the factory with an identity in. E0F0 holds the
#: Infineon attestation private key and E0E0 the certificate that matches it;
#: overwriting either destroys that identity for good and no amount of
#: reprovisioning brings it back. TrustM.write_data() refuses them unless
#: explicitly told otherwise. The chip's own metadata also marks both
#: `change: never`, but that is a second line of defence, not the first.
PROVISIONED_OIDS = {
    0xE0F0: "Infineon attestation private key",
    0xE0E0: "Infineon device certificate",
}

#: General-purpose data objects, from the factory metadata dump in
#: subs/optiga-trust-m-overview/data/object_dumps/trust_m1_json.txt. Nothing
#: factory-provisioned lives in these, so they are where to experiment.
#: `read: always`, `change: lcso < operational` throughout.
DATA_OBJECT_SIZES = {
    **{oid: 100 for oid in range(0xF1D0, 0xF1DC)},   # 12 x 100 bytes
    0xF1E0: 1500,
    0xF1E1: 1500,
    0xE0E1: 1728, 0xE0E2: 1728, 0xE0E3: 1728,        # spare certificate slots
    0xE0E8: 1200, 0xE0E9: 1200, 0xE0EF: 1200,
}

#: The smallest of those, and the conventional scratchpad. 100 bytes, and
#: nothing else in the chip cares what is in it.
#: Every object a V1 chip actually has, with a short description.
#:
#: The library's own eOID_d enum (OIDS above) covers only 20 of these - it has
#: no name for the monotonic counters, the trust anchors, the platform binding
#: secret or any of the general-purpose data objects. Names and descriptions
#: come from the SRM's data object table; the list is checked against the
#: 41-object V1 factory dump in subs/optiga-trust-m-overview.
KNOWN_OIDS = {
    0xE0C0: "lifecycle state, global (LcsG)",
    0xE0C1: "security status, global",
    0xE0C2: "coprocessor UID",
    0xE0C3: "sleep mode activation delay",
    0xE0C4: "current limitation",
    0xE0C5: "security event counter",
    0xE0C6: "maximum communication buffer size",
    0xE0E0: "Infineon device certificate",
    0xE0E1: "certificate slot 1",
    0xE0E2: "certificate slot 2",
    0xE0E3: "certificate slot 3",
    0xE0E8: "root CA certificate 1",
    0xE0E9: "root CA certificate 2",
    0xE0EF: "trust anchor, protected update",
    0xE0F0: "Infineon attestation private key",
    0xE0F1: "ECC key slot 1",
    0xE0F2: "ECC key slot 2",
    0xE0F3: "ECC key slot 3",
    0xE0FC: "RSA key slot 1",
    0xE0FD: "RSA key slot 2",
    0xE120: "monotonic counter 1",
    0xE121: "monotonic counter 2",
    0xE122: "monotonic counter 3",
    0xE123: "monotonic counter 4",
    0xE140: "platform binding secret",
    0xF1C0: "lifecycle state, application (LcsA)",
    0xF1C1: "security status, application",
    0xF1C2: "error codes",
    **{oid: f"data object, 100 bytes ({oid - 0xF1D0 + 1} of 12)"
       for oid in range(0xF1D0, 0xF1DC)},
    0xF1E0: "data object, 1500 bytes (1 of 2)",
    0xF1E1: "data object, 1500 bytes (2 of 2)",
}

#: Session contexts. Volatile, and not listed in KNOWN_OIDS because they have
#: no metadata of their own to read.
SESSION_OID_RANGE = range(0xE100, 0xE104)

SCRATCH_OID = 0xF1D0

#: Key slots safe to generate into. E0F0 is the factory attestation key and is
#: absent on purpose; the chip's own metadata says `change: never`, but
#: TrustM.generate_keypair() refuses before it gets that far.
SCRATCH_KEY_SLOTS = (0xE0F1, 0xE0F2, 0xE0F3)

#: The attestation key. Overwriting it destroys the identity that E0E0's
#: certificate attests to, permanently and with no way back.
PROVISIONED_KEY_SLOTS = {0xE0F0: "Infineon attestation private key"}

#: USB vendor IDs an RP2040 running this firmware may enumerate under. The core
#: declares 0x239a for the Trinkey, but a sketch built by it can come up as
#: 0x2e8a ("PicoArduino") instead - see bridge-plan.md section 4.
RP2040_VIDS = (0x2E8A, 0x239A)
