# MIT License
#
# Copyright (c) 2023 MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
UDP-Client implementation to communicate with Hikvision cameras.
"""

__all__ = ["SADPClient", "hik_code"]

import socket

from hiktools.sadp.message import SADPMessage


class SADPClient:
    """A simple UDP wrapper client.

    This clas implements basic funtionalities of an UDP socket sending data
    from UDP broadcast. The with directive can be used and __iter__ is also
    implemented in order to iterate over reveiced SADPMessages.
    """

    def __init__(self, port: int = 37020, timeout: int = 2) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.settimeout(timeout)
        self._address = ("239.255.255.250", port)
        self.buf_size = 2048

    def __enter__(self) -> "SADPClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        """Closes the underlying socket."""
        self._sock.close()

    def write(self, message: SADPMessage) -> int:
        """Writes the given message and returnes the amount of bytes sent."""
        return self.write_bytes(bytes(message)) if message else -1

    def write_bytes(self, buffer: bytes) -> int:
        """Directly writes bytes to the UDP broadcast"""
        return self._sock.sendto(buffer, self._address)

    def recv_next(self, bufsize: int = 1024) -> bytes:
        """Receives the next bytes."""
        return self._sock.recv(bufsize)

    def __iter__(self):
        try:
            while True:
                data = self.recv_next(self.buf_size)
                yield SADPMessage(response=data)
        except socket.timeout:
            pass


def hik_code(serial: str, timestamp: tuple) -> str:
    """Generates the old Hikvision reset code.

    Arguments:
    :param serial: The device's serial number.
    :type serial: str
    :param timestamp: A timestamp of the following format: (day, month, year)
    :type timestamp: str

    :returns: The generated reset code (can be used within a reset packet).
    :rtype: str
    """
    magic = 0
    result = ""
    day = int(timestamp[0])
    month = int(timestamp[1])
    year = int(timestamp[2])

    composed = serial + year + month + day
    for i, val in enumerate(composed):
        magic += (ord(val) * (i + 1)) ^ (i + 1)

    magic = str((magic * 0x686B7773) & 0xFFFFFFFF)
    for i, c0 in enumerate(magic):
        if c0 < 51:
            result += chr(c0 + 33)
        elif c0 < 53:
            result += chr(c0 + 62)
        elif c0 < 55:
            result += chr(c0 + 47)
        elif c0 < 57:
            result += chr(c0 + 66)
        else:
            result += chr(c0)

    return result
