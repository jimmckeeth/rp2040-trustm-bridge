"""
The API you actually use.

`raw.py` speaks the wire protocol; this speaks about the chip. Commands return
parsed objects, and the chip's per-call limits are handled here rather than
being pushed onto the caller.
"""

from dataclasses import dataclass

from . import const, raw
from .errors import DeviceError, ProtocolError
from .transport import SerialTransport

#: SRM "Error Codes": offset + length ran past the end of the object. Reading
#: is how you discover an object's size, so this is an expected answer, not a
#: fault.
BOUNDARY_EXCEEDED = 0x08

#: SRM "Error Codes": the chip checked a signature and it did not match. An
#: answer, not a fault - verify_on_chip() turns it back into False.
SIGNATURE_INVALID = 0x2C

#: SRM "Error Codes": a counter is already at its threshold.
COUNTER_EXHAUSTED = 0x0E


@dataclass(frozen=True)
class BridgeInfo:
    """What PING reports. Firmware only - says nothing about the chip."""

    proto: int
    firmware: str
    lib_version: str
    max_line: int
    max_rand: int
    chip_open: bool
    #: Defaulted so that a board running firmware older than 0.2.0, which does
    #: not report it, still parses.
    max_data: int = 0

    @classmethod
    def from_tokens(cls, info):
        return cls(
            proto=int(info.get("proto", 0)),
            firmware=info.get("fw", "unknown"),
            lib_version=info.get("lib", "unknown"),
            max_line=int(info.get("maxline", 0)),
            max_rand=int(info.get("maxrand", 0)),
            chip_open=info.get("open") == "1",
            max_data=int(info.get("maxdata", 0)),
        )

    def __str__(self):
        return (f"{self.firmware}, protocol {self.proto}, "
                f"OPTIGA host library {self.lib_version}, "
                f"chip {'open' if self.chip_open else 'not yet opened'}")


@dataclass(frozen=True)
class KeyPair:
    """What KEYGEN produced.

    `public` and `private` are the chip's own encodings, kept so that nothing is
    lost; `public_key` and `private_key` are the usable objects. `private` is
    None unless the key was exported, which is the normal case - the point of
    the chip is that the private key never leaves it.
    """

    slot: object
    curve: str
    usage: str
    public: bytes
    private: bytes = None

    @property
    def public_key(self):
        from . import keys
        if self.curve.startswith("rsa"):
            return keys.rsa_public_key(self.public)
        return keys.public_key(self.public, self.curve)

    @property
    def private_key(self):
        from . import keys
        if self.private is None:
            raise ValueError(
                "this key was generated inside the chip and cannot be read out; "
                "pass slot='export' if you want a key you can hold"
            )
        return keys.private_key(self.private, self.curve)

    @property
    def point(self):
        """The uncompressed EC point, 0x04 || X || Y."""
        from . import keys
        return keys.public_point(self.public)

    def __str__(self):
        if self.private:
            where = "exported to the host"
        elif isinstance(self.slot, str):
            where = f"{self.slot} key"
        else:
            where = f"slot 0x{self.slot:04X}"
        return f"{self.curve} {self.usage} key, {where}"


@dataclass(frozen=True)
class CoprocessorUid:
    """The 27 bytes of OID 0xE0C2, split into its documented fields.

    Shields from one wafer lot can differ in as little as two bytes, so a
    single read is not enough to tell one board from another - see
    trustm_boards/identify.py, which requires several agreeing reads.
    """

    raw: bytes

    @property
    def hex(self):
        return self.raw.hex().upper()

    @property
    def fields(self):
        return {name: self.raw[start:end].hex().upper()
                for name, start, end in const.UID_FIELDS}

    @property
    def build_number(self):
        return self.fields["build_number"]

    @property
    def revision(self):
        """'V1', 'V3', or None if the build number is not one we know."""
        entry = const.BUILD_TO_REVISION.get(self.build_number)
        return entry[0] if entry else None

    @property
    def firmware_version(self):
        entry = const.BUILD_TO_REVISION.get(self.build_number)
        return entry[1] if entry else None

    def __str__(self):
        if self.revision:
            return f"Trust M {self.revision}, firmware {self.firmware_version}"
        return f"Trust M, unrecognised build {self.build_number}"


class TrustM:
    """A Trust M reached through a Trinkey running trustm_bridge.

        with TrustM() as tm:
            print(tm.ping())
            print(tm.uid())
            print(tm.random(32).hex())
    """

    def __init__(self, port=None, transport=None, **kwargs):
        self.transport = transport or SerialTransport(port=port, **kwargs)
        self._max_data = None

    @property
    def port(self):
        return self.transport.port

    def close(self):
        self.transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False

    # ------------------------------------------------------------- commands

    def ping(self, check=True):
        """Check the bridge firmware is alive and see what it supports.

        Raises ProtocolError if the board speaks a protocol this package does
        not. Pass check=False to report what is there regardless - which is the
        whole point of ping when the board turns out to be running something
        old, so the CLI does exactly that.
        """
        info = BridgeInfo.from_tokens(raw.ping(self.transport))
        if check and info.proto != const.PROTO_VERSION:
            raise ProtocolError(
                f"board speaks protocol {info.proto}, this package speaks "
                f"{const.PROTO_VERSION}. Reflash it: python -m trustm flash"
            )
        return info

    def commands(self):
        """The command names this firmware supports, as a set."""
        return set(raw.commands(self.transport))

    def uid(self):
        """Read the Coprocessor UID. This is the first command to touch the
        chip, so it is also the check that the shield is attached and alive."""
        return CoprocessorUid(raw.uid(self.transport))

    def random(self, length=const.RAND_LEN_DEFAULT, source="trng"):
        """`length` random bytes from the chip's TRNG (or DRNG).

        GetRandom accepts 8 to 256 bytes per call, so this issues as many calls
        as it takes and, for fewer than 8 bytes, asks for the minimum and keeps
        what was wanted. Every byte returned still came from the chip.
        """
        if length < 0:
            raise ValueError("length must not be negative")
        if length == 0:
            return b""

        out = bytearray()
        while len(out) < length:
            want = min(length - len(out), const.RAND_LEN_MAX)
            ask = max(want, const.RAND_LEN_MIN)
            out.extend(raw.rand(self.transport, ask, source)[:want])
        return bytes(out)

    def read_data(self, oid, offset=0, length=None):
        """Read a data object, following it across as many calls as it takes.

        With `length` unset this reads to the end of the object. The chip has
        no "how big is it" command, so the end is found by reading until a call
        comes back short - or, for an object that happens to be an exact
        multiple of the chunk size, until the next read runs off the end and
        the chip says so (device error 0x08).
        """
        chunk = self._chunk
        out = bytearray()

        while length is None or len(out) < length:
            want = chunk if length is None else min(length - len(out), chunk)
            try:
                block = raw.rdata(self.transport, oid, offset + len(out), want)
            except DeviceError as exc:
                if length is None and out and exc.device_code == BOUNDARY_EXCEEDED:
                    break
                raise
            out.extend(block)
            if len(block) < want:
                break               # the object ended
        return bytes(out)

    def write_data(self, oid, data, offset=0, erase=True,
                   allow_provisioned=False):
        """Write a data object, in as many calls as it takes.

        `erase` discards the object first, so its length becomes exactly what
        was written - which is what "write this object" normally means. Pass
        `erase=False` to patch bytes in place and leave the rest alone. Only
        the first chunk erases; a chunked write that erased each time would
        keep throwing away what came before it.

        Refuses the factory-provisioned objects, because overwriting E0F0 or
        E0E0 destroys the chip's Infineon identity permanently. Pass
        `allow_provisioned=True` if that is genuinely what you want.
        """
        if isinstance(oid, str):
            oid = int(oid, 16)
        if oid in const.PROVISIONED_OIDS and not allow_provisioned:
            raise ValueError(
                f"0x{oid:04X} holds the {const.PROVISIONED_OIDS[oid]}, and "
                f"overwriting it cannot be undone. Pass "
                f"allow_provisioned=True if you mean it."
            )
        data = bytes(data)
        if not data:
            raise ValueError("nothing to write")

        chunk = self._chunk
        written = 0
        while written < len(data):
            block = data[written:written + chunk]
            mode = "erase" if (erase and written == 0) else "write"
            raw.wdata(self.transport, oid, offset + written, block, mode)
            written += len(block)
        return written

    # -------------------------------------------------------------- internal

    def metadata(self, oid):
        """An object's metadata, decoded. See metadata.py.

        Always permitted, even for objects whose contents you cannot read, so
        this is the way to find out why a read was refused.
        """
        from . import metadata as meta

        if isinstance(oid, str):
            oid = int(oid, 16)
        return meta.parse(raw.rmeta(self.transport, oid), oid)

    def objects(self, oids=None):
        """Metadata for every object, as {oid: Metadata}.

        Skips OIDs the chip rejects, so this works as a survey of what is
        actually present rather than needing a correct list up front - the
        equivalent of the factory dump, taken from your own chip.
        """
        from .errors import CommandError

        found = {}
        for oid in sorted(set(oids if oids is not None else const.KNOWN_OIDS)):
            try:
                found[oid] = self.metadata(oid)
            except CommandError:
                continue                # not present on this chip
        return found

    def write_metadata(self, oid, fields, allow_lifecycle=False,
                       allow_lock=False, allow_provisioned=False):
        """Write metadata, refusing the changes that cannot be undone.

        `fields` is {name: bytes} as Metadata.fields uses, holding only the tags
        being changed - the chip merges rather than replacing, so a partial
        write leaves the other tags alone.

        Three refusals, because the chip has none of its own and every one of
        these is permanent:

        - **lcso** advances an object's lifecycle, and lifecycle never goes
          back. E0F1-E0F3 carry `change: lcso < operational`, so advancing
          theirs to operational makes them immutable for good.
        - an access condition of **NEV** locks that operation out for ever.
        - **E0F0 and E0E0** hold the factory identity.
        """
        from . import metadata as meta

        if isinstance(oid, str):
            oid = int(oid, 16)
        if not fields:
            raise ValueError("nothing to write")

        provisioned = dict(const.PROVISIONED_OIDS)
        provisioned.update(const.PROVISIONED_KEY_SLOTS)
        if oid in provisioned and not allow_provisioned:
            raise ValueError(
                f"0x{oid:04X} holds the {provisioned[oid]}, and its metadata is "
                f"part of that identity. Pass allow_provisioned=True if you "
                f"mean it."
            )
        if "lcso" in fields and not allow_lifecycle:
            state = meta.LIFECYCLE.get(bytes(fields["lcso"])[0], "an unknown state")
            raise ValueError(
                f"setting lcso to {state} cannot be undone - lifecycle only "
                f"ever moves forward, and for E0F1-E0F3 reaching operational "
                f"makes the object permanently immutable. Pass "
                f"allow_lifecycle=True if you mean it."
            )
        if not allow_lock:
            for which in meta.ACCESS_TAGS:
                if which in fields and bytes(fields[which]) == b"\xff":
                    raise ValueError(
                        f"setting {which} to NEV locks that operation out of "
                        f"0x{oid:04X} permanently. Pass allow_lock=True if you "
                        f"mean it."
                    )

        blob = meta.build(fields)
        return raw.wmeta(self.transport, oid, blob)

    def certificate(self, oid=0xE0E0):
        """The X.509 certificate in a certificate object, parsed.

        Needs the `cryptography` package. See cert.py for the container the
        chip wraps these in - it is not a bare DER certificate, which is the
        one thing everybody assumes first.
        """
        from . import cert as _cert
        return _cert.load(self.read_data(oid))

    def certificate_chain(self, oid=0xE0E0):
        """Every certificate in a certificate object, device certificate first.

        The factory object holds one. A host that writes a full chain into a
        slot gets them all back here.
        """
        from . import cert as _cert
        return _cert.load_chain(self.read_data(oid))

    def generate_keypair(self, slot=0xE0F1, curve="p256", usage="sign",
                         allow_provisioned=False):
        """Generate an ECC keypair and return a KeyPair.

        `slot` may be an OID, "session" for a volatile key that dies with the
        next reset, or "export" to have the private key handed back instead of
        kept - export and a slot are mutually exclusive in the chip's API.

        Generating into E0F0 would overwrite the Infineon attestation key that
        E0E0's certificate attests to. The chip's own metadata should refuse it,
        but that is not a good enough reason to send the command.
        """
        from . import keys

        if isinstance(slot, str) and slot.lower() not in ("session", "export"):
            slot = int(slot, 16)
        if slot in const.PROVISIONED_KEY_SLOTS and not allow_provisioned:
            raise ValueError(
                f"0x{slot:04X} holds the {const.PROVISIONED_KEY_SLOTS[slot]}, "
                f"and overwriting it destroys the identity E0E0's certificate "
                f"attests to. Pass allow_provisioned=True if you mean it."
            )
        if curve not in keys.CURVE_NAMES:
            raise ValueError(
                f"unknown curve {curve!r}; expected one of "
                f"{', '.join(keys.CURVE_NAMES)}"
            )
        for one in usage.split("+"):
            if one not in keys.USAGE_NAMES:
                raise ValueError(
                    f"unknown key usage {one!r}; expected some of "
                    f"{', '.join(keys.USAGE_NAMES)} joined by '+'"
                )

        public, private = raw.keygen(self.transport, slot, curve, usage)
        return KeyPair(slot=slot, curve=curve, usage=usage,
                       public=public, private=private)

    def sign(self, digest, slot=0xE0F1):
        """ECDSA over `digest`, returned as a complete DER signature.

        The chip emits r and s without the outer SEQUENCE; this puts it back, so
        what comes out of here verifies against any ordinary tool. `raw.sign()`
        returns the chip's bytes untouched if you want to see them.
        """
        from . import keys
        return keys.der_signature(raw.sign(self.transport, slot, digest))

    def hash(self, data):
        """SHA-256, computed on the chip, at any length.

        Slower than hashing on the desktop and not a substitute for it. It is
        here because it is what the chip's own digest-consuming commands are
        fed by, and because it is a cheap way to prove the link is intact.

        Anything past one line's worth goes through the chip's streaming form -
        start, updates, finalize - so the caller never has to know where the
        line limit falls.
        """
        data = bytes(data)
        chunk = self._chunk
        if len(data) <= chunk:
            return raw.hash_(self.transport, data)

        raw.hash_start(self.transport)
        for offset in range(0, len(data), chunk):
            raw.hash_update(self.transport, data[offset:offset + chunk])
        return raw.hash_finalize(self.transport)

    def hash_file(self, path):
        """SHA-256 of a file, computed on the chip, read a chunk at a time."""
        chunk = self._chunk
        raw.hash_start(self.transport)
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(chunk), b""):
                raw.hash_update(self.transport, block)
        return raw.hash_finalize(self.transport)

    def verify_on_chip(self, key, signature, digest, curve="p256"):
        """ECDSA verification performed by the chip, not the host.

        The chip reports a bad signature as device error 0x2C, which is the
        right thing on the wire and the wrong thing for a caller - "is this
        signature good" should answer with a bool, not an exception.

        `key` may be a KeyPair, a BIT STRING or a raw point; `signature` may be
        the chip's bare r,s or a complete DER one, though the chip wants the
        bare form and it is unwrapped here if need be.
        """
        from . import keys
        from .errors import DeviceError

        public = key.public if isinstance(key, KeyPair) else bytes(key)
        if public[0] == 0x04:                       # a bare point
            public = keys.bit_string(public)
        signature = bytes(signature)
        if signature[0] == 0x30:                    # strip the DER SEQUENCE
            _, signature, _ = keys.der_tlv(signature)

        try:
            raw.verify(self.transport, public, digest, signature, curve)
        except DeviceError as exc:
            if exc.device_code == SIGNATURE_INVALID:
                return False
            raise
        return True

    def key_agreement(self, peer_public_key, slot=0xE0F1, curve="p256"):
        """ECDH against a peer's public key. Returns the shared secret.

        The secret is exported to the host, which is the only way to check it
        against the other side - a real protocol would leave it in a session
        object instead and derive from it there.

        `peer_public_key` may be a raw EC point or an object exposing
        `public_bytes`, so a key straight from `cryptography` works.
        """
        from . import keys
        from cryptography.hazmat.primitives import serialization

        if hasattr(peer_public_key, "public_bytes"):
            peer_public_key = peer_public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)
        peer_public_key = bytes(peer_public_key)
        if peer_public_key[0] == 0x04:
            peer_public_key = keys.bit_string(peer_public_key)
        return raw.ecdh(self.transport, slot, peer_public_key, curve)

    def counter(self, oid):
        """A monotonic counter as (value, threshold)."""
        data = self.read_data(oid)
        if len(data) != 8:
            raise ValueError(
                f"0x{oid:04X} holds {len(data)} bytes, not a counter's 8"
            )
        return int.from_bytes(data[:4], "big"), int.from_bytes(data[4:], "big")

    def set_counter(self, oid, value=0, threshold=0xFFFFFFFF):
        """Set a counter's value and threshold. Needs the object still writable."""
        blob = value.to_bytes(4, "big") + threshold.to_bytes(4, "big")
        return self.write_data(oid, blob)

    def increment_counter(self, oid, step=1):
        """Bump a counter and return its new (value, threshold).

        The value is read back rather than assumed, because a step that would
        carry it past the threshold **saturates at the threshold and still
        succeeds**. Only an increment attempted at the threshold fails, with
        device error 0x0E - so a caller that trusts its own arithmetic here
        will be wrong without being told.
        """
        if not 1 <= step <= 0xFF:
            raise ValueError(f"step must be 1..255, not {step}")
        raw.ctrinc(self.transport, oid, step)
        return self.counter(oid)

    def generate_rsa_keypair(self, slot=0xE0FC, bits=2048, usage="sign",
                             allow_provisioned=False):
        """Generate an RSA keypair. Returns a KeyPair with curve=f'rsa{bits}'.

        Whether this works is a property of the silicon rather than the
        library: RSA is an OPTIGA SKU option. These boards do have it.
        """
        if isinstance(slot, str) and slot.lower() not in ("session", "export"):
            slot = int(slot, 16)
        if slot in const.PROVISIONED_KEY_SLOTS and not allow_provisioned:
            raise ValueError(
                f"0x{slot:04X} holds the {const.PROVISIONED_KEY_SLOTS[slot]}. "
                f"Pass allow_provisioned=True if you mean it."
            )
        public = raw.rsagen(self.transport, slot, bits, usage)
        return KeyPair(slot=slot, curve=f"rsa{bits}", usage=usage, public=public)

    def rsa_sign(self, digest, slot=0xE0FC, scheme="sha256"):
        """RSA PKCS#1 v1.5 signature. Complete as it stands, unlike ECDSA."""
        return raw.rsasign(self.transport, slot, digest, scheme)

    def verify(self, key, signature, digest, curve="p256"):
        """Check a signature on the desktop. Never touches the chip.

        Here because it is the other half of sign() and the first thing anyone
        wants after producing one, not because the chip is involved.
        """
        from . import keys
        return keys.verify(key, signature, digest, curve)

    @property
    def _chunk(self):
        """Largest payload one RDATA/WDATA may carry, as the board reports it.

        Asked once and remembered: it is a firmware constant, and paying for a
        PING before every chunk of a long read would be silly.
        """
        if self._max_data is None:
            self._max_data = self.ping().max_data or const.DATA_LEN_MAX
        return self._max_data
