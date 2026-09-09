"""
Serial framing for the Trust M bridge.

The wire protocol is deliberately plain text (see bridge-plan.md section 3.1):
hex doubles the payload size, and in exchange the whole thing is drivable by
hand from a serial monitor and framing bugs simply do not exist.

    > 7 RAND 32 trng
    < 7 OK RAND 9F2C...
    < 7 ERR RAND 0x8007 random
    # anything else

The tag - `7` above - is a correlation tag, not a sequence number. It is chosen
by the host, echoed verbatim by the board, and never parsed by either side; the
board is free to give it back as a string because nothing about it is
arithmetic. It answers one question: which of my requests is this? After a
timeout or a board reset, replies to abandoned commands are still in flight, and
matching on the tag discards them instead of leaving the host permanently one
reply behind - a failure mode where every reply looks well-formed and every
answer is one command stale.

The echoed command is a second, independent check on the same thing. Command
names are not unique across retries, so it cannot replace the tag; it catches
the cases the tag alone would not, and makes a raw capture readable.

The firmware accepts the tag and the '>' prefix as optional, so that a human at
a serial monitor can type `RAND 32`. This class always sends both. Anything
driving the bridge programmatically should do the same - without a tag there is
no correlation, and the resulting desync is invisible until something retries.
"""

import time

import serial
from serial.tools import list_ports

from . import const
from .errors import PortNotFound, ProtocolError, Timeout, from_status

DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT = 5.0


def find_ports():
    """Serial ports that look like an RP2040. Ordered, may be empty."""
    return [p for p in sorted(list_ports.comports(), key=lambda p: p.device)
            if p.vid in const.RP2040_VIDS]


def find_port():
    """The single RP2040 serial port, or raise PortNotFound."""
    ports = find_ports()
    if not ports:
        raise PortNotFound("No RP2040 board found. Is it plugged in?")
    if len(ports) > 1:
        listed = ", ".join(p.device for p in ports)
        raise PortNotFound(
            f"More than one RP2040 board connected ({listed}). Pass port= to pick one."
        )
    return ports[0].device


def wait_for_port(port, timeout=10.0):
    """Block until `port` exists, e.g. after a flash re-enumerates the board."""
    import os

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(port):
            return True
        time.sleep(0.2)
    return False


class SerialTransport:
    """One command at a time over USB CDC, with tag-and-command resync."""

    def __init__(self, port=None, baudrate=DEFAULT_BAUDRATE, timeout=DEFAULT_TIMEOUT,
                 log=None):
        self.port = port or find_port()
        self.baudrate = baudrate
        self.timeout = timeout
        #: Called with every line sent and received, prefixed. Handy in the CLI.
        self.log = log
        self._serial = None
        self._tag = 0
        self.open()

    # ------------------------------------------------------------ lifecycle

    def open(self):
        if self._serial is not None:
            return
        try:
            self._serial = serial.Serial(self.port, self.baudrate, timeout=0.1)
        except serial.SerialException as exc:
            raise PortNotFound(f"could not open {self.port}: {exc}") from exc
        # A board that has been running unattended may have queued output, and
        # a half-typed line from a serial monitor would corrupt our first
        # command. Drop both.
        time.sleep(0.05)
        self._serial.reset_input_buffer()
        self._serial.write(b"\n")
        self._serial.flush()

    def close(self):
        if self._serial is not None:
            self._serial.close()
            self._serial = None

    def reconnect(self, timeout=10.0):
        """Reopen after the board resets and USB re-enumerates."""
        self.close()
        if not wait_for_port(self.port, timeout):
            raise PortNotFound(f"{self.port} did not come back within {timeout}s")
        self.open()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False

    # -------------------------------------------------------------- command

    def command(self, name, *args, timeout=None):
        """Send one command, return the reply's tokens after OK.

        Raises CommandError on ERR, Timeout if nothing matching arrives.
        """
        if self._serial is None:
            self.open()

        self._tag = (self._tag + 1) & 0x7FFFFFFF
        tag = str(self._tag)

        parts = [tag, name]
        parts.extend(str(a) for a in args)
        line = "> " + " ".join(parts)
        if len(line) + 1 > const.MAX_LINE:
            raise ProtocolError(
                f"command is {len(line) + 1} bytes, over MAX_LINE ({const.MAX_LINE})"
            )

        if self.log:
            self.log(line)
        self._serial.write((line + "\n").encode("ascii"))
        self._serial.flush()

        return self._await_reply(tag, name, timeout)

    def _await_reply(self, tag, name, timeout):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Timeout(f"no reply to {name} (tag {tag}) within "
                              f"{self.timeout if timeout is None else timeout}s")
            self._serial.timeout = min(remaining, 0.5)
            raw = self._serial.readline()
            if not raw:
                continue

            line = raw.decode("ascii", "replace").strip()
            if not line:
                continue
            if self.log:
                self.log(line)

            if line.startswith("#"):
                continue                        # unsolicited note
            if not line.startswith("< "):
                continue                        # not a reply at all

            tokens = line[2:].split()
            if len(tokens) < 3:
                raise ProtocolError(f"malformed reply: {line!r}")
            reply_tag, status, reply_cmd = tokens[0], tokens[1], tokens[2]

            if reply_tag != tag:
                continue                        # stale, from before a timeout

            # '-' is the board saying it never identified a command: an
            # overflowed line, or a tag with nothing after it. The tag matched,
            # so the error is still ours to raise.
            if reply_cmd not in (name, "-"):
                raise ProtocolError(
                    f"reply to tag {tag} says {reply_cmd}, sent {name} "
                    f"(firmware older than 0.3.0 does not echo the command): "
                    f"{line!r}"
                )

            if status == "OK":
                return tokens[3:]
            if status == "ERR":
                if len(tokens) < 5:
                    raise ProtocolError(f"malformed ERR reply: {line!r}")
                try:
                    code = int(tokens[3], 16)
                except ValueError:
                    raise ProtocolError(f"unparseable status code: {line!r}") from None
                raise from_status(code, tokens[4], name)
            raise ProtocolError(f"unknown reply status {status!r}: {line!r}")
