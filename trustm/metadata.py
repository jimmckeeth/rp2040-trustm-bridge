"""
Object metadata: what an object is, how big, and who may touch it.

Metadata is a constructed TLV under tag 0x20, and every object has some -
including ones whose contents you are not allowed to read. That is the useful
part: reading metadata is always permitted, so this is how you find out *why*
a read was refused.

    20 0b  c0 01 01  d0 03 e1 fc 07  d3 01 00
    ^  ^   ^         ^               ^
    |  |   |         |               execute: always
    |  |   |         change: LcsO < operational
    |  |   lifecycle state: creation
    |  length
    constructed TLV

The tables below are transcribed from the Solution Reference Manual sections
'Access Condition Identifier and Operators', 'Types' and 'Life Cycle Status',
and are checked against the 41-object factory dump in
subs/optiga-trust-m-overview/data/object_dumps/trust_m1_json.txt - which is
V1 silicon, the same as these boards.

Everything here is pure parsing; nothing in this module talks to the chip.
"""

from dataclasses import dataclass

#: The constructed TLV every metadata blob is wrapped in.
CONSTRUCTED_TAG = 0x20

#: Metadata tags. V1 does not implement 0xD8 or 0xF0 - the chip answers
#: 0x8001 rather than ignoring them, so they are listed to be recognised, not
#: to be written.
TAGS = {
    0xC0: "lcso",
    0xC1: "version",
    0xC4: "max_size",
    0xC5: "used_size",
    0xD0: "change",
    0xD1: "read",
    0xD3: "execute",
    0xD8: "metadata_update",     # not on V1
    0xE0: "algorithm",
    0xE1: "key_usage",
    0xE8: "type",
    0xF0: "reset_type",          # not on V1
}

TAG_BY_NAME = {name: tag for tag, name in TAGS.items()}

#: Tags whose value is an access-condition expression rather than a number.
ACCESS_TAGS = ("change", "read", "execute")

V1_UNSUPPORTED = ("metadata_update", "reset_type")

#: Lifecycle states. One-way: creation -> initialization -> operational ->
#: termination, and never back. SRM table 'Life Cycle Status'.
LIFECYCLE = {
    0x01: "creation",
    0x03: "initialization",
    0x07: "operational",
    0x0F: "termination",
}

#: Data object types, SRM table 'Types'. V1 does not support the last two.
OBJECT_TYPES = {
    0x00: "byte_string",
    0x01: "up_counter",
    0x11: "trust_anchor",
    0x12: "device_cert",          # SRM calls the type DEVCERT
    0x21: "pre_shared_secret",
    0x22: "platform_binding",
    0x23: "protected_update_secret",   # not on V1
    0x31: "authorization_reference",   # not on V1
}

ALGORITHMS = {0x03: "secp256r1", 0x04: "secp384r1"}

KEY_USAGE_BITS = {
    0x01: "authentication",
    0x02: "encryption",
    0x10: "sign",
    0x20: "key_agreement",
}

#: Access-condition identifiers, as (name, total byte length). The length
#: includes the identifier itself, which is what makes the expression walkable
#: without knowing what any of it means.
AC_IDENTIFIERS = {
    0x00: ("always", 1),
    0x10: ("sec_sta_g", 2),
    0x20: ("conf", 3),
    0x21: ("int", 3),
    0x23: ("auto", 3),
    0x40: ("luc", 3),
    0x70: ("lcs_g", 3),
    0x90: ("sec_sta_a", 3),
    0xE0: ("lcs_a", 3),
    0xE1: ("lcs_o", 3),
    0xFF: ("never", 1),
}

#: Comparison qualifiers, which sit inside a 3-byte lifecycle term.
AC_COMPARISONS = {0xFA: "==", 0xFB: ">", 0xFC: "<"}

#: Boolean operators, which join whole terms. These are the ones that make an
#: expression more than a single term.
AC_BOOLEANS = {0xFD: "&&", 0xFE: "||"}

#: Identifiers whose third byte is a lifecycle state rather than half an OID.
AC_LIFECYCLE_TERMS = ("lcs_g", "lcs_a", "lcs_o")


class MetadataError(ValueError):
    """Metadata did not parse."""


@dataclass(frozen=True)
class Metadata:
    """One object's metadata, decoded.

    `fields` keeps the raw value of every tag in the order the chip sent them,
    so re-encoding is exact and an unknown tag is never silently dropped.
    """

    oid: int
    raw: bytes
    fields: dict

    def __getitem__(self, name):
        return self.fields[name]

    def get(self, name, default=None):
        return self.fields.get(name, default)

    @property
    def lifecycle(self):
        value = self.fields.get("lcso")
        return LIFECYCLE.get(value[0]) if value else None

    @property
    def max_size(self):
        return _integer(self.fields.get("max_size"))

    @property
    def used_size(self):
        return _integer(self.fields.get("used_size"))

    @property
    def object_type(self):
        value = self.fields.get("type")
        # SRM: "In case this tag is not present, the data object is represented
        # by an unrestricted array of bytes" - i.e. absent means byte_string.
        if value is None:
            return "byte_string"
        return OBJECT_TYPES.get(value[0], f"unknown(0x{value[0]:02X})")

    @property
    def algorithm(self):
        value = self.fields.get("algorithm")
        return ALGORITHMS.get(value[0], f"unknown(0x{value[0]:02X})") if value else None

    @property
    def key_usage(self):
        value = self.fields.get("key_usage")
        if value is None:
            return None
        return [name for bit, name in sorted(KEY_USAGE_BITS.items())
                if value[0] & bit]

    def access(self, which):
        """The access condition for 'change', 'read' or 'execute', as text."""
        value = self.fields.get(which)
        return format_access(value) if value is not None else None

    @property
    def locked(self):
        """True if this object can never be changed again.

        Either the change condition is NEV outright, or it is gated on a
        lifecycle state the object has already passed - lifecycle only moves
        forward, so that gate can never reopen.
        """
        value = self.fields.get("change")
        if value is None:
            return False
        if value == b"\xff":
            return True
        return not _lifecycle_gate_open(value, self.fields.get("lcso"))

    def __str__(self):
        parts = [f"0x{self.oid:04X}", self.object_type]
        if self.lifecycle:
            parts.append(f"lcso={self.lifecycle}")
        if self.max_size is not None:
            size = f"{self.used_size}/{self.max_size}" if self.used_size is not None \
                   else str(self.max_size)
            parts.append(f"size={size}")
        if self.algorithm:
            parts.append(f"alg={self.algorithm}")
        if self.key_usage:
            parts.append(f"usage={'+'.join(self.key_usage)}")
        for which in ACCESS_TAGS:
            text = self.access(which)
            if text is not None:
                parts.append(f"{which}={text}")
        if self.locked:
            parts.append("LOCKED")
        return "  ".join(parts)


def parse(data, oid=0):
    """Decode a metadata blob into a Metadata.

    Unknown tags are kept under their hex name rather than dropped, so that a
    V3 chip or a firmware update does not silently lose information here.
    """
    data = bytes(data)
    if len(data) < 2:
        raise MetadataError(f"metadata is {len(data)} bytes, too short to parse")
    if data[0] != CONSTRUCTED_TAG:
        raise MetadataError(
            f"expected the constructed tag 0x{CONSTRUCTED_TAG:02X}, "
            f"found 0x{data[0]:02X}"
        )
    if data[1] != len(data) - 2:
        raise MetadataError(
            f"metadata says {data[1]} bytes follow, {len(data) - 2} are present"
        )

    fields = {}
    offset = 2
    while offset < len(data):
        if offset + 2 > len(data):
            raise MetadataError(f"metadata ends mid-tag at offset {offset}")
        tag, length = data[offset], data[offset + 1]
        offset += 2
        if offset + length > len(data):
            raise MetadataError(
                f"tag 0x{tag:02X} claims {length} bytes, "
                f"{len(data) - offset} remain"
            )
        fields[TAGS.get(tag, f"0x{tag:02X}")] = data[offset:offset + length]
        offset += length
    return Metadata(oid=oid, raw=data, fields=fields)


def build(fields):
    """Encode {name: bytes} back into a metadata blob.

    The inverse of parse(): `build(parse(blob).fields)` returns `blob` when the
    order is preserved, which is why fields is an ordinary dict rather than
    anything that would sort it.
    """
    body = bytearray()
    for name, value in fields.items():
        tag = TAG_BY_NAME.get(name)
        if tag is None:
            try:
                tag = int(name, 16)
            except (TypeError, ValueError):
                raise MetadataError(f"unknown metadata field {name!r}") from None
        value = bytes(value)
        if len(value) > 0xFF:
            raise MetadataError(f"{name} is {len(value)} bytes, over 255")
        body += bytes([tag, len(value)]) + value

    if len(body) > 0xFF:
        raise MetadataError(f"metadata is {len(body)} bytes, over 255")
    return bytes([CONSTRUCTED_TAG, len(body)]) + bytes(body)


# ----------------------------------------------------- access-condition text


def parse_access(value):
    """An access-condition expression as a list of terms and operators.

    Terms are tuples; operators are the plain strings "&&" and "||". Walking
    the expression needs only the identifier's length, so an identifier this
    module does not recognise still leaves the rest of it parseable.
    """
    value = bytes(value)
    parts = []
    offset = 0
    while offset < len(value):
        byte = value[offset]
        if byte in AC_BOOLEANS:
            parts.append(AC_BOOLEANS[byte])
            offset += 1
            continue

        name, size = AC_IDENTIFIERS.get(byte, (f"0x{byte:02X}", 1))
        term = value[offset:offset + size]
        if len(term) != size:
            raise MetadataError(
                f"access condition ends mid-term: {value.hex()}"
            )
        parts.append((name, term))
        offset += size
    return parts


def format_access(value):
    """An access-condition expression as readable text.

    'always', 'never', 'lcso < operational',
    'lcso < operational || conf(0xE140)'.
    """
    try:
        parts = parse_access(value)
    except MetadataError:
        return bytes(value).hex().upper()

    out = []
    for part in parts:
        if isinstance(part, str):
            out.append(part)
            continue
        name, term = part
        if len(term) == 1:
            out.append(name)
        elif name in AC_LIFECYCLE_TERMS and len(term) == 3:
            comparison = AC_COMPARISONS.get(term[1], f"0x{term[1]:02X}")
            state = LIFECYCLE.get(term[2], f"0x{term[2]:02X}")
            out.append(f"{name} {comparison} {state}")
        elif len(term) == 3:
            out.append(f"{name}(0x{term[1]:02X}{term[2]:02X})")
        else:
            out.append(f"{name}(0x{term[1:].hex().upper()})")
    return " ".join(out)


def _integer(value):
    return int.from_bytes(value, "big") if value else None


def _lifecycle_gate_open(condition, lcso):
    """True if a change condition gated on LcsO could still be satisfied.

    Only the object's own lifecycle is considered: LcsG and LcsA are global and
    can be read separately, and guessing at them here would make `locked` claim
    more certainty than it has.
    """
    if lcso is None:
        return True
    current = lcso[0]
    try:
        parts = parse_access(condition)
    except MetadataError:
        return True

    saw_gate = False
    for part in parts:
        if isinstance(part, str):
            if part == "||":
                return True         # some other branch may still allow it
            continue
        name, term = part
        if name == "always":
            return True
        if name != "lcs_o" or len(term) != 3:
            continue
        saw_gate = True
        comparison, target = term[1], term[2]
        if comparison == 0xFC and current < target:
            return True
        if comparison == 0xFB and current > target:
            return True
        if comparison == 0xFA and current == target:
            return True
    return not saw_gate
