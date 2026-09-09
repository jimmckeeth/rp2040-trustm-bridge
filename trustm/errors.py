"""
Exception hierarchy for the Trust M bridge.

    TrustMError
      TransportError        the serial link itself
        PortNotFound        no board matched
        Timeout             no reply within the deadline
        ProtocolError       a reply arrived but did not parse
      CommandError          the firmware replied ERR
        BridgeError         0xFFxx - the firmware refused the command
        OptigaError         a host-library status code
          DeviceError       0x8xxx - the chip itself refused

The status-code tables come from const.py, which is generated from the headers
the firmware is built against, so a decoded message here always matches the
library actually running on the board.
"""

from . import const


class TrustMError(Exception):
    """Base for everything this package raises."""


class TransportError(TrustMError):
    """The serial link failed, independently of anything the chip did."""


class PortNotFound(TransportError):
    """No serial port matched, or more than one did."""


class Timeout(TransportError):
    """The board did not answer in time."""


class ProtocolError(TransportError):
    """A reply arrived but was not a well-formed bridge reply."""


class CommandError(TrustMError):
    """The firmware answered ERR."""

    def __init__(self, status, stage, command=None):
        self.status = status
        self.stage = stage
        self.command = command
        super().__init__(str(self))

    @property
    def name(self):
        """Symbolic name for the status code, or None if it is unknown."""
        return None

    @property
    def detail(self):
        """Human-readable explanation, or None if the code is unknown."""
        return None

    def __str__(self):
        parts = [f"0x{self.status:04X}"]
        if self.name:
            parts.append(self.name)
        if self.detail:
            parts.append(f"({self.detail})")
        where = f"{self.command} {self.stage}" if self.command else self.stage
        return f"{where}: " + " ".join(parts)


class BridgeError(CommandError):
    """The firmware rejected the command before it reached the chip."""

    @property
    def name(self):
        entry = const.BRIDGE_ERRORS.get(self.status)
        return entry[0] if entry else None

    @property
    def detail(self):
        entry = const.BRIDGE_ERRORS.get(self.status)
        return entry[1] if entry else None


class OptigaError(CommandError):
    """A host-library status code came back from the board."""

    @property
    def name(self):
        entry = const.RETURN_CODES.get(self.status)
        return entry[0] if entry else None

    @property
    def detail(self):
        entry = const.RETURN_CODES.get(self.status)
        return entry[1] if entry else None


class DeviceError(OptigaError):
    """The chip executed the command and refused it.

    ``device_code`` is the low byte, per the SRM "Error Codes" table. This is
    the one to read closely: 0x07 (access conditions not satisfied) and 0x01
    (invalid OID) account for most of what goes wrong while exploring.
    """

    @property
    def device_code(self):
        return self.status & 0xFF

    @property
    def name(self):
        return "OPTIGA_DEVICE_ERROR"

    @property
    def detail(self):
        known = const.DEVICE_ERRORS.get(self.device_code)
        code = f"0x{self.device_code:02X}"
        return f"{code} {known}" if known else f"{code}, not in the SRM table"


def from_status(status, stage, command=None):
    """Build the right exception for a status code the firmware reported."""
    if status in const.BRIDGE_ERRORS or status >= 0xFF00:
        return BridgeError(status, stage, command)
    if status >= const.DEVICE_ERROR_BASE:
        return DeviceError(status, stage, command)
    return OptigaError(status, stage, command)
