"""
Desktop access to an OPTIGA Trust M through a Trinkey RP2040 running the
trustm_bridge firmware.

    from trustm import TrustM

    with TrustM() as tm:
        print(tm.ping())
        print(tm.uid(), tm.uid().hex)
        print(tm.random(32).hex())

The chip is I2C-only, so it cannot be reached from a desktop directly. The
Infineon host library stays on the microcontroller and this drives it one
command at a time over USB CDC. See bridge-plan.md for the design and
firmware/trustm_bridge for the other half.
"""

from .device import BridgeInfo, CoprocessorUid, KeyPair, TrustM
from .errors import (
    BridgeError,
    CommandError,
    DeviceError,
    OptigaError,
    PortNotFound,
    ProtocolError,
    Timeout,
    TransportError,
    TrustMError,
)
from .transport import SerialTransport, find_port, find_ports

__version__ = "0.1.0"

__all__ = [
    "BridgeError",
    "BridgeInfo",
    "CommandError",
    "CoprocessorUid",
    "DeviceError",
    "KeyPair",
    "OptigaError",
    "PortNotFound",
    "ProtocolError",
    "SerialTransport",
    "Timeout",
    "TransportError",
    "TrustM",
    "TrustMError",
    "find_port",
    "find_ports",
]
