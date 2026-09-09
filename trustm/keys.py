"""
Keys and signatures, and the two shapes the chip returns them in.

Neither is what a general-purpose library expects, and both are silent about
it - you get a parse error a long way from the cause. They are handled here so
that `raw.py` can keep reporting exactly what the chip sent.

**The public key is a bare DER BIT STRING**, not a SubjectPublicKeyInfo::

    03 42 00 04 <X 32 bytes> <Y 32 bytes>      P-256, 68 bytes
    ^  ^  ^  ^
    |  |  |  uncompressed-point marker
    |  |  unused bits
    |  length
    BIT STRING

There is no AlgorithmIdentifier, so nothing says which curve it is - the caller
has to remember what it asked for. `cryptography` will not load it as a public
key; the point inside it loads fine with `from_encoded_point`.

**The signature has no outer SEQUENCE.** The chip emits the two INTEGERs for r
and s and stops::

    02 21 00DFC0...  02 20 7F3ADB...      69 bytes for P-256

A complete DER ECDSA signature wraps those in `30 <len>`. Without the wrapper
every verifier rejects it, which reads like a bad signature rather than a
framing problem - so this is worth knowing before you go looking for the fault
in the key.

**An exported private key** is a DER OCTET STRING around the raw scalar::

    04 20 <32 bytes>                          P-256, 34 bytes
"""

from .cert import CertificateError, _require_cryptography

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:                                     # pragma: no cover
    pass

BIT_STRING_TAG = 0x03
OCTET_STRING_TAG = 0x04
INTEGER_TAG = 0x02
SEQUENCE_TAG = 0x30

#: Curve name -> (cryptography curve, private scalar bytes, matching digest).
#: The digest size is the one the chip will accept for that curve; it does no
#: hashing itself, so a digest of the wrong length is simply refused.
CURVES = {
    "p256": ("SECP256R1", 32, 32),
    "p384": ("SECP384R1", 48, 48),
}

#: What the firmware accepts, so the CLI and the docs agree with the sketch.
CURVE_NAMES = tuple(CURVES)
USAGE_NAMES = ("sign", "auth", "agree", "encrypt")


def curve(name):
    """The `cryptography` curve object for one of CURVE_NAMES."""
    _require_cryptography()
    try:
        attr = CURVES[name][0]
    except KeyError:
        raise ValueError(
            f"unknown curve {name!r}; expected one of {', '.join(CURVE_NAMES)}"
        ) from None
    return getattr(ec, attr)()


def digest_size(name):
    """Digest length the chip expects when signing with this curve."""
    return CURVES[name][2]


def public_point(data):
    """The uncompressed EC point inside the chip's BIT STRING public key.

    A bare point (already starting with 0x04) passes through, so this can be
    handed whatever a caller happens to have.
    """
    data = bytes(data)
    if not data:
        raise CertificateError("public key is empty")
    if data[0] == 0x04:
        return data                         # already a point
    if data[0] != BIT_STRING_TAG:
        raise CertificateError(
            f"expected a DER BIT STRING (0x03) or an uncompressed point (0x04), "
            f"found 0x{data[0]:02X}"
        )
    if len(data) < 4:
        raise CertificateError("public key is too short to hold a point")

    length = data[1]
    if length & 0x80:
        raise CertificateError(
            "long-form BIT STRING length - the chip does not emit these, so "
            "this is not a public key from KEYGEN"
        )
    if 2 + length != len(data):
        raise CertificateError(
            f"BIT STRING says {length} bytes, {len(data) - 2} are present"
        )
    if data[2] != 0:
        raise CertificateError(f"{data[2]} unused bits in an EC point")
    return data[3:]


def public_key(data, curve_name="p256"):
    """A usable public key from what KEYGEN returned.

    The curve has to be supplied because the chip's encoding does not carry it.
    """
    _require_cryptography()
    return ec.EllipticCurvePublicKey.from_encoded_point(
        curve(curve_name), public_point(data)
    )


def private_scalar(data):
    """The raw scalar inside an exported private key's OCTET STRING."""
    data = bytes(data)
    if len(data) < 2 or data[0] != OCTET_STRING_TAG:
        raise CertificateError(
            f"expected a DER OCTET STRING (0x04), found "
            f"0x{data[0]:02X}" if data else "private key is empty"
        )
    length = data[1]
    if 2 + length != len(data):
        raise CertificateError(
            f"OCTET STRING says {length} bytes, {len(data) - 2} are present"
        )
    return data[2:]


def private_key(data, curve_name="p256"):
    """A usable private key from an exported KEYGEN result."""
    _require_cryptography()
    scalar = private_scalar(data)
    return ec.derive_private_key(
        int.from_bytes(scalar, "big"), curve(curve_name)
    )


def der_tlv(data, offset=0):
    """One DER TLV as (tag, value, next_offset), long-form lengths included.

    The chip's RSA public key needs this - it is 275 bytes, so its BIT STRING
    carries a two-byte length, which the EC path never has to deal with.
    """
    data = bytes(data)
    if offset + 2 > len(data):
        raise CertificateError(f"DER ends at offset {offset}")
    tag, first = data[offset], data[offset + 1]
    offset += 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or offset + count > len(data):
            raise CertificateError("malformed DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    if offset + length > len(data):
        raise CertificateError(
            f"DER object claims {length} bytes, {len(data) - offset} remain"
        )
    return tag, data[offset:offset + length], offset + length


def rsa_public_key(data):
    """A usable public key from what RSAGEN returned.

    Same trick as the EC one and the same omission: a bare BIT STRING with no
    AlgorithmIdentifier, wrapping a PKCS#1 RSAPublicKey rather than an EC
    point. `cryptography` will not load either one directly.
    """
    _require_cryptography()
    from cryptography.hazmat.primitives.asymmetric import rsa

    tag, bits, _ = der_tlv(data)
    if tag != BIT_STRING_TAG:
        raise CertificateError(
            f"expected a DER BIT STRING (0x03), found 0x{tag:02X}"
        )
    if not bits or bits[0] != 0:
        raise CertificateError("expected zero unused bits in an RSA public key")

    tag, sequence, _ = der_tlv(bits, 1)
    if tag != SEQUENCE_TAG:
        raise CertificateError(
            f"expected a PKCS#1 RSAPublicKey SEQUENCE, found 0x{tag:02X}"
        )
    _, modulus, offset = der_tlv(sequence, 0)
    _, exponent, _ = der_tlv(sequence, offset)
    return rsa.RSAPublicNumbers(
        int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
    ).public_key()


def rsa_verify(key, signature, digest):
    """True if `signature` is `key`'s PKCS#1 v1.5 signature over `digest`."""
    _require_cryptography()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

    if not isinstance(key, rsa.RSAPublicKey):
        key = rsa_public_key(key)
    algorithm = {32: hashes.SHA256(), 48: hashes.SHA384()}.get(len(digest))
    if algorithm is None:
        raise ValueError(
            f"digest is {len(digest)} bytes; expected 32 (SHA-256) or 48 (SHA-384)"
        )
    try:
        key.verify(bytes(signature), bytes(digest), padding.PKCS1v15(),
                   utils.Prehashed(algorithm))
    except InvalidSignature:
        return False
    return True


#: What the chip will accept from RSAGEN.
RSA_SIZES = (1024, 2048)


def bit_string(point):
    """Wrap a raw EC point in the BIT STRING the chip expects from a host.

    ECDH and VERIFY take a peer public key in the same encoding KEYGEN
    produces, so a key generated on the desktop has to be dressed up to match.
    """
    point = bytes(point)
    return bytes([BIT_STRING_TAG, len(point) + 1, 0x00]) + point


def der_signature(raw):
    """Wrap the chip's bare r,s INTEGERs in the SEQUENCE they are missing.

    Idempotent: a signature that already has its SEQUENCE is returned unchanged,
    so this is safe to apply to anything signature-shaped.
    """
    raw = bytes(raw)
    if not raw:
        raise CertificateError("signature is empty")
    if raw[0] == SEQUENCE_TAG:
        return raw                          # already complete
    if raw[0] != INTEGER_TAG:
        raise CertificateError(
            f"expected a DER INTEGER (0x02) at the start of a signature, "
            f"found 0x{raw[0]:02X}"
        )

    # Walk the two INTEGERs rather than trusting the length, so a truncated
    # reply is caught here instead of surfacing as a verification failure.
    offset = 0
    for which in ("r", "s"):
        if offset + 2 > len(raw):
            raise CertificateError(f"signature ends before its {which} value")
        if raw[offset] != INTEGER_TAG:
            raise CertificateError(
                f"expected an INTEGER for {which}, found 0x{raw[offset]:02X}"
            )
        offset += 2 + raw[offset + 1]
    if offset != len(raw):
        raise CertificateError(
            f"signature has {len(raw) - offset} bytes after r and s"
        )

    if len(raw) > 0x7F:                     # long-form length, as P-384 needs
        return bytes([SEQUENCE_TAG, 0x81, len(raw)]) + raw
    return bytes([SEQUENCE_TAG, len(raw)]) + raw


def verify(key, signature, digest, curve_name="p256"):
    """True if `signature` is `key`'s signature over `digest`.

    Takes the signature in either shape - the chip's bare r,s or a complete DER
    one - and the key as an object, a BIT STRING, or a raw point.
    """
    _require_cryptography()
    from cryptography.hazmat.primitives import hashes

    if not isinstance(key, ec.EllipticCurvePublicKey):
        key = public_key(key, curve_name)

    algorithm = {32: hashes.SHA256(), 48: hashes.SHA384()}.get(len(digest))
    if algorithm is None:
        raise ValueError(
            f"digest is {len(digest)} bytes; expected 32 (SHA-256) or 48 (SHA-384)"
        )
    try:
        key.verify(der_signature(signature), digest,
                   ec.ECDSA(_Prehashed(algorithm)))
    except InvalidSignature:
        return False
    return True


def public_pem(key):
    """PEM SubjectPublicKeyInfo for a public key, which is what other tools read.

    The chip cannot produce this itself - its BIT STRING carries no curve - so
    it is assembled here from the curve the caller asked KEYGEN for.
    """
    _require_cryptography()
    from cryptography.hazmat.primitives import serialization
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _Prehashed(algorithm):
    from cryptography.hazmat.primitives.asymmetric import utils
    return utils.Prehashed(algorithm)
