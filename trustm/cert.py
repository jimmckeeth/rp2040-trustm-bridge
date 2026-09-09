"""
The certificate objects, and the container Infineon wraps them in.

E0E0-E0E3 do not hold a bare certificate. They hold a TLS-style structure with
three nested lengths in front of the DER:

    C0  <u16>        tag, then the length of everything after these three bytes
        <u24>        length of the certificate list
        <u24> <DER>  one certificate, repeated to fill the list

This is why the object looks like it parses and then does not. `openssl x509
-inform der` appears to work on the raw bytes because it reads the first DER
structure it finds and ignores the nine bytes in front of it; Python's
`cryptography` insists the input is exactly one certificate and refuses. Both
are behaving correctly, which makes it a confusing hour if you assume the tool
is wrong.

`cryptography` is imported here and nowhere else in the package, so it stays an
optional dependency: everything except the certificate commands works without
it.
"""

from . import const

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    HAVE_CRYPTOGRAPHY = True
except ImportError:                                     # pragma: no cover
    HAVE_CRYPTOGRAPHY = False

#: Where the bundled Infineon CAs live, relative to the repository root. They
#: arrive with the optiga-trust-m-overview submodule rather than being copied
#: in, so they stay whatever Infineon published.
CA_DIRECTORY = "subs/optiga-trust-m-overview/data/certificates"

CONTAINER_TAG = 0xC0

#: A DER SEQUENCE, which is how a bare certificate starts. Distinguishing the
#: two by first byte is enough: 0xC0 is not a valid ASN.1 universal tag here.
DER_SEQUENCE_TAG = 0x30


class CertificateError(ValueError):
    """A certificate object did not hold what it claimed to."""


def _require_cryptography():
    if not HAVE_CRYPTOGRAPHY:
        raise CertificateError(
            "the `cryptography` package is needed to parse certificates: "
            "pip install cryptography"
        )


def is_empty(data):
    """True if a certificate object has never been written.

    An unused slot reads back as its full length in zero bytes, not as a short
    read - so "is there a certificate here" is a question about content, not
    about length.
    """
    return not data or not any(data)


def split_container(data):
    """The DER certificates inside a Trust M certificate object.

    Returns a list of `bytes`, outermost (the device certificate) first.

    A bare DER certificate is accepted as well as the container, because that is
    what ends up in one of these objects when a host writes one directly - the
    chip stores whatever it is given and does not check the shape.
    """
    data = bytes(data)
    if is_empty(data):
        raise CertificateError(
            f"certificate object is empty ({len(data)} zero bytes)"
        )

    if data[0] == DER_SEQUENCE_TAG:
        return [data]                       # written by a host, not Infineon
    if data[0] != CONTAINER_TAG:
        raise CertificateError(
            f"expected 0x{CONTAINER_TAG:02X} or 0x{DER_SEQUENCE_TAG:02X} at the "
            f"start of a certificate object, found 0x{data[0]:02X}"
        )
    if len(data) < 9:
        raise CertificateError(
            f"certificate container is {len(data)} bytes, too short for its "
            f"9-byte header"
        )

    # Each length counts only what follows it, so each one is checked against
    # what is actually there rather than trusted. A truncated read is the
    # likely cause, and saying so beats a DER parse error further down.
    outer = int.from_bytes(data[1:3], "big")
    if 3 + outer != len(data):
        raise CertificateError(
            f"container says {outer} bytes follow its header, but {len(data) - 3} "
            f"are present - a truncated read?"
        )
    chain_length = int.from_bytes(data[3:6], "big")
    if 6 + chain_length != len(data):
        raise CertificateError(
            f"certificate list says {chain_length} bytes, but {len(data) - 6} "
            f"are present"
        )

    certs = []
    offset = 6
    while offset < len(data):
        if offset + 3 > len(data):
            raise CertificateError("certificate list ends mid-length")
        length = int.from_bytes(data[offset:offset + 3], "big")
        offset += 3
        if length == 0 or offset + length > len(data):
            raise CertificateError(
                f"certificate at offset {offset} claims {length} bytes, "
                f"{len(data) - offset} remain"
            )
        certs.append(data[offset:offset + length])
        offset += length

    if not certs:
        raise CertificateError("certificate container holds no certificates")
    return certs


def load_chain(data):
    """Parsed certificates from a Trust M certificate object, device cert first."""
    _require_cryptography()
    return [x509.load_der_x509_certificate(der) for der in split_container(data)]


def load(data):
    """The device certificate from a Trust M certificate object."""
    return load_chain(data)[0]


def to_pem(cert):
    """PEM text for one certificate."""
    _require_cryptography()
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# ------------------------------------------------------------------ CA store


def load_cas(directory=None):
    """Every CA certificate in `directory`, keyed by subject.

    Reads both DER and PEM, because Infineon ships a mixture and the file
    extension does not say which is which.
    """
    _require_cryptography()
    import glob
    import os

    if directory is None:
        directory = os.path.join(_repo_root(), CA_DIRECTORY)

    cas = []
    for path in sorted(glob.glob(os.path.join(directory, "*.crt")) +
                       glob.glob(os.path.join(directory, "*.pem"))):
        blob = open(path, "rb").read()
        for loader in (x509.load_der_x509_certificate,
                       x509.load_pem_x509_certificate):
            try:
                cas.append((os.path.basename(path), loader(blob)))
                break
            except Exception:
                continue
    return cas


def _repo_root():
    import os
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _key_id(cert, extension):
    try:
        value = cert.extensions.get_extension_for_class(extension).value
    except x509.ExtensionNotFound:
        return None
    return getattr(value, "digest", None) or getattr(value, "key_identifier", None)


def find_issuer(cert, cas):
    """The CA that issued `cert`, as (filename, certificate), or None.

    Matches on the authority key identifier rather than on the issuer name.
    Names repeat across Infineon's CA generations and the key identifier is what
    actually binds a certificate to the key that signed it - which matters here,
    because the bundled set contains several CAs with confusingly similar names.
    """
    _require_cryptography()
    wanted = _key_id(cert, x509.AuthorityKeyIdentifier)
    for name, ca in cas:
        if wanted is not None and _key_id(ca, x509.SubjectKeyIdentifier) == wanted:
            return name, ca
    for name, ca in cas:                    # no AKI, or no CA carried an SKI
        if ca.subject == cert.issuer:
            return name, ca
    return None


def verify_signature(cert, issuer):
    """True if `issuer`'s public key actually signed `cert`."""
    _require_cryptography()
    key = issuer.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            raise CertificateError(f"unsupported issuer key type: {type(key).__name__}")
    except InvalidSignature:
        return False
    return True


def build_chain(cert, cas=None):
    """Follow `cert` towards a root through whatever CAs are available.

    Returns a list of steps, one per link, each a dict with `cert`, `issuer`,
    `issuer_file`, `verified` and `self_signed`. The list stops at a
    self-signed root, or at the first certificate whose issuer is not in the
    store - and the caller is expected to say which of those happened, because
    "the chain is fine as far as it goes" and "the chain is complete" are very
    different claims.
    """
    _require_cryptography()
    if cas is None:
        cas = load_cas()

    steps = []
    seen = set()
    current = cert
    while True:
        self_signed = current.subject == current.issuer
        found = find_issuer(current, cas)
        if self_signed and found is None:
            found = ("(itself)", current)

        step = {
            "cert": current,
            "self_signed": self_signed,
            "issuer": found[1] if found else None,
            "issuer_file": found[0] if found else None,
            "verified": verify_signature(current, found[1]) if found else None,
        }
        steps.append(step)

        if found is None or self_signed:
            break
        fingerprint = found[1].fingerprint(hashes.SHA256())
        if fingerprint in seen:             # a cross-signed loop, not a chain
            break
        seen.add(fingerprint)
        current = found[1]
    return steps


def chain_is_complete(steps):
    """True if every link verified and the last one is a self-signed root."""
    return bool(steps) and steps[-1]["self_signed"] and all(
        step["verified"] for step in steps
    )


def describe(cert):
    """The fields worth printing, as an ordered list of (label, value)."""
    _require_cryptography()
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"EC {key.curve.name} ({key.curve.key_size}-bit)"
    elif isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA {key.key_size}-bit"
    else:
        key_desc = type(key).__name__

    return [
        ("subject", cert.subject.rfc4514_string()),
        ("issuer", cert.issuer.rfc4514_string()),
        ("serial", f"{cert.serial_number:X}"),
        ("valid from", str(cert.not_valid_before_utc)),
        ("valid to", str(cert.not_valid_after_utc)),
        ("public key", key_desc),
        ("signature", cert.signature_algorithm_oid._name),
        ("SHA-256", cert.fingerprint(hashes.SHA256()).hex().upper()),
    ]


def public_point(cert):
    """The uncompressed EC point from a certificate's public key.

    This is the form SIGN's counterpart needs: verifying a signature the chip
    produced means checking it against the key in the chip's own certificate.
    """
    _require_cryptography()
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise CertificateError("certificate does not hold an EC public key")
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


#: The certificate objects, with what the chip ships in each. Only E0E0 is
#: populated at the factory; the rest are empty and writable.
CERTIFICATE_OIDS = {
    0xE0E0: "Infineon device certificate (factory-provisioned)",
    0xE0E1: "certificate slot 1 (empty)",
    0xE0E2: "certificate slot 2 (empty)",
    0xE0E3: "certificate slot 3 (empty)",
}
