"""
One function per bridge command, bytes in and bytes out.

Nothing here interprets or works around the chip: a call maps to exactly one
OPTIGA operation and its limits are the chip's limits. Convenience - chunking,
padding, parsing into objects - belongs in device.py, so that this module stays
a readable inventory of what the firmware actually supports.
"""

from . import const
from .errors import ProtocolError


def ping(transport):
    """Firmware identity and limits. Does not touch the chip.

    Returns a dict of the reply's key=value tokens, e.g.::

        {'proto': '1', 'fw': 'trustm_bridge/0.1.0', 'lib': '1.30.885',
         'maxline': '4096', 'maxrand': '256', 'open': '0'}
    """
    tokens = transport.command("PING")
    info = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        if not sep:
            raise ProtocolError(f"PING returned a bare token: {token!r}")
        info[key] = value
    return info


def commands(transport):
    """The HELP command: the names this firmware answers to.

    The prose HELP prints goes out as `#` notes, which the transport drops, so
    what arrives here is just the list - which makes this a feature check as
    well as documentation ("does this board have RDATA?").
    """
    return transport.command("HELP")


def uid(transport):
    """Coprocessor UID, OID 0xE0C2. 27 bytes."""
    tokens = transport.command("UID")
    if len(tokens) != 1:
        raise ProtocolError(f"UID returned {len(tokens)} tokens, expected 1")
    data = _unhex(tokens[0], "UID")
    if len(data) != const.UID_LENGTH:
        raise ProtocolError(
            f"UID is {len(data)} bytes, expected {const.UID_LENGTH}"
        )
    return data


def rand(transport, length=None, source="trng"):
    """One GetRandom call. `length` must be 8..256; `source` is trng or drng.

    Out-of-range lengths are left to the firmware to reject rather than being
    caught here, so that the chip's real limits stay visible at this layer.

    `length=None` sends no length at all and takes the firmware's default, which
    is the same RAND_LEN_DEFAULT asserted below - the point is to exercise the
    default over the wire, not to guess at it.
    """
    if source not in const.RNG_TYPES:
        raise ValueError(
            f"unknown random source {source!r}; expected one of "
            f"{', '.join(sorted(const.RNG_TYPES))}"
        )
    if length is None:
        length = const.RAND_LEN_DEFAULT
        tokens = transport.command("RAND", source)          # firmware default
    else:
        tokens = transport.command("RAND", int(length), source)
    if len(tokens) != 1:
        raise ProtocolError(f"RAND returned {len(tokens)} tokens, expected 1")
    data = _unhex(tokens[0], "RAND")
    if len(data) != length:
        raise ProtocolError(f"RAND returned {len(data)} bytes, asked for {length}")
    return data


def rdata(transport, oid, offset=0, length=None):
    """One GetDataObject call. Returns whatever the object holds from `offset`.

    `length` is a ceiling rather than a demand: the chip hands back the bytes
    it actually has, so a short reply means the object ended, not that the read
    failed. Omitting it asks for the largest transfer the firmware will frame.
    """
    args = [_oid(oid), int(offset)]
    if length is not None:
        args.append(int(length))
    tokens = transport.command("RDATA", *args)
    if not tokens:
        return b""                      # an empty object, not an error
    if len(tokens) != 1:
        raise ProtocolError(f"RDATA returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "RDATA")


def wdata(transport, oid, offset, data, mode="write"):
    """One SetDataObject call. Returns the number of bytes the board wrote.

    `mode` is "write" (overwrite in place, leaving the rest of the object) or
    "erase" (discard the object first, so its length becomes what was written).

    Nothing here refuses a dangerous OID - see TrustM.write_data(), which does.
    """
    if mode not in const.WRITE_MODES:
        raise ValueError(
            f"unknown write mode {mode!r}; expected one of "
            f"{', '.join(const.WRITE_MODES)}"
        )
    if not data:
        raise ValueError("nothing to write")
    tokens = transport.command("WDATA", _oid(oid), int(offset),
                               bytes(data).hex().upper(), mode)
    if len(tokens) != 1:
        raise ProtocolError(f"WDATA returned {len(tokens)} tokens, expected 1")
    try:
        written = int(tokens[0])
    except ValueError:
        raise ProtocolError(f"WDATA returned {tokens[0]!r}, expected a count") from None
    if written != len(data):
        raise ProtocolError(f"WDATA wrote {written} bytes, sent {len(data)}")
    return written


def rmeta(transport, oid):
    """One GetDataObject-metadata call. Returns the raw constructed TLV.

    Metadata is always readable, even for objects whose contents are not - so
    this works where rdata() is refused, and is how you find out why.
    """
    tokens = transport.command("RMETA", _oid(oid))
    if len(tokens) != 1:
        raise ProtocolError(f"RMETA returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "RMETA")


def wmeta(transport, oid, data):
    """One SetDataObject-metadata call. Returns the number of bytes written.

    `data` is a complete constructed TLV, sent unexamined. Nothing here refuses
    a one-way change - see TrustM.write_metadata(), which does.
    """
    if not data:
        raise ValueError("nothing to write")
    tokens = transport.command("WMETA", _oid(oid), bytes(data).hex().upper())
    if len(tokens) != 1:
        raise ProtocolError(f"WMETA returned {len(tokens)} tokens, expected 1")
    try:
        written = int(tokens[0])
    except ValueError:
        raise ProtocolError(f"WMETA returned {tokens[0]!r}, expected a count") from None
    if written != len(data):
        raise ProtocolError(f"WMETA wrote {written} bytes, sent {len(data)}")
    return written


def keygen(transport, slot, curve="p256", usage="sign"):
    """One GenKeyPair call. Returns (public_key, private_key).

    `slot` is an OID, the string "session" for a volatile key, or "export" to
    have the chip hand the private key back instead of keeping it - those last
    two are the chip's own vocabulary, and export and a slot are mutually
    exclusive because export_private_key turns the API's `private_key` argument
    from an OID into a buffer.

    Both values are exactly what the chip emitted: a DER BIT STRING and, when
    exported, a DER OCTET STRING. keys.py turns them into usable objects.
    """
    args = [slot if isinstance(slot, str) else _oid(slot), curve, usage]
    tokens = transport.command("KEYGEN", *args)
    if len(tokens) not in (1, 2):
        raise ProtocolError(
            f"KEYGEN returned {len(tokens)} tokens, expected 1 or 2"
        )
    public = _unhex(tokens[0], "KEYGEN")
    private = _unhex(tokens[1], "KEYGEN") if len(tokens) == 2 else None
    return public, private


def sign(transport, slot, digest):
    """One CalcSign call. Returns the signature exactly as the chip emitted it.

    That is r and s as DER INTEGERs with **no outer SEQUENCE** - see keys.py.
    Nothing is repaired here, so that this layer keeps reporting what actually
    came off the chip.
    """
    if not digest:
        raise ValueError("nothing to sign")
    args = [slot if isinstance(slot, str) else _oid(slot),
            bytes(digest).hex().upper()]
    tokens = transport.command("SIGN", *args)
    if len(tokens) != 1:
        raise ProtocolError(f"SIGN returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "SIGN")


def hash_(transport, data):
    """One Hash command. SHA-256 of `data`, computed on the chip.

    Named with a trailing underscore only to leave the builtin alone; the
    command is HASH.
    """
    if not data:
        raise ValueError("nothing to hash")
    tokens = transport.command("HASH", bytes(data).hex().upper())
    if len(tokens) != 1:
        raise ProtocolError(f"HASH returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "HASH")


def hash_start(transport):
    """Begin a streaming hash. The context lives on the chip until HASHFIN."""
    transport.command("HASHSTART")


def hash_update(transport, data):
    """Add to a streaming hash. Returns the number of bytes accepted."""
    if not data:
        raise ValueError("nothing to add")
    tokens = transport.command("HASHUPD", bytes(data).hex().upper())
    if len(tokens) != 1:
        raise ProtocolError(f"HASHUPD returned {len(tokens)} tokens, expected 1")
    return int(tokens[0])


def hash_finalize(transport):
    """Finish a streaming hash and return the digest."""
    tokens = transport.command("HASHFIN")
    if len(tokens) != 1:
        raise ProtocolError(f"HASHFIN returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "HASHFIN")


def verify(transport, public_key, digest, signature, curve="p256"):
    """One VerifySign command, checked by the chip rather than the host.

    Returns True, or raises DeviceError 0x802C when the chip rejects it - a
    failed verification is a device error there, not a false. device.py turns
    that back into a bool.
    """
    transport.command("VERIFY", curve, bytes(public_key).hex().upper(),
                      bytes(digest).hex().upper(), bytes(signature).hex().upper())
    return True


def ecdh(transport, slot, peer_public_key, curve="p256"):
    """One CalcSharedSecret call, with the secret exported to the host."""
    tokens = transport.command("ECDH",
                               slot if isinstance(slot, str) else _oid(slot),
                               curve, bytes(peer_public_key).hex().upper())
    if len(tokens) != 1:
        raise ProtocolError(f"ECDH returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "ECDH")


def ctrinc(transport, oid, step=1):
    """One update-counter call. Returns nothing.

    Deliberately nothing: a step that would pass the threshold saturates at it
    and still succeeds, so there is no number here that would be true. Read the
    counter afterwards - TrustM.increment_counter() does.
    """
    transport.command("CTRINC", _oid(oid), int(step))


def rsagen(transport, slot, bits=2048, usage="sign"):
    """One RSA GenKeyPair call. Returns the public key as the chip encodes it.

    Whether this works at all is a property of the silicon: RSA is an OPTIGA
    SKU option, and the library being built with it says nothing about the chip.
    """
    if bits not in (1024, 2048):
        raise ValueError(f"RSA key size must be 1024 or 2048, not {bits}")
    tokens = transport.command("RSAGEN",
                               slot if isinstance(slot, str) else _oid(slot),
                               int(bits), usage)
    if len(tokens) != 1:
        raise ProtocolError(f"RSAGEN returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "RSAGEN")


def rsasign(transport, slot, digest, scheme="sha256"):
    """One RSA CalcSign call. PKCS#1 v1.5, complete as it stands."""
    if not digest:
        raise ValueError("nothing to sign")
    tokens = transport.command("RSASIGN",
                               slot if isinstance(slot, str) else _oid(slot),
                               bytes(digest).hex().upper(), scheme)
    if len(tokens) != 1:
        raise ProtocolError(f"RSASIGN returned {len(tokens)} tokens, expected 1")
    return _unhex(tokens[0], "RSASIGN")


def _oid(oid):
    """OIDs go on the wire as four hex digits, however they arrived."""
    if isinstance(oid, str):
        oid = int(oid, 16)
    if not 0 <= oid <= 0xFFFF:
        raise ValueError(f"OID out of range: 0x{oid:X}")
    return f"{oid:04X}"


def _unhex(token, command):
    try:
        return bytes.fromhex(token)
    except ValueError as exc:
        raise ProtocolError(f"{command} returned invalid hex: {exc}") from None
