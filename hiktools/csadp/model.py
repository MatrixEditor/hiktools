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
__doc__ = """
CSADP packets are wrapped into objects that support the ``__bytes__`` method to
dynamically create the byte buffer.

This module covers the conversion between binary data to MAC- and IP addressees
and defines base classes for SADPPackets.
"""

import struct
import binascii

from socket import AF_INET6, inet_aton, inet_ntoa, inet_ntop, inet_pton

from hiktools.csadp.checksum import get_checksum
from hiktools.csadp.uarray import LITTLE_ENDIAN, to_uint16_buf

__all__ = [
    "inet_stomac",
    "inet_mactos",
    "inet_stoip",
    "inet_iptos",
    "EthernetHeader",
    "SADPHeader",
    "SADPPacket",
    "SERVER_PREFIX",
    "CLIENT_PREFIX",
    "PACKET_TYPE",
    "inet6_stoip",
    "inet6_iptos",
    "SADPPayload",
    "payload",
]

CLIENT_PREFIX = 0x42
SERVER_PREFIX = 0xF6

PACKET_TYPE = {
    "DeviceOnlineRequest": 0x02,
    "Inquiry": 0x03,
    "InquiryResponse": 0x04,
    "UpdateIP": 0x06,
    "UpdateIPResponse": 0x07,
    "ResetPassword": 0x0A,
    "ResetPasswordResponse": 0x0B,
    "CMSInfo": 0x0C,
    "CMSInfoResponse": 0x0D,
    "ModifyNetParam": 0x10,
    "ModifyNetParamResponse": 0x11,
}

PAYLOAD_TYPE = {
    # structure of this dict
    # int: class<? extends SADPPayload>, ...
}


def inet_stomac(mac: str) -> bytes:
    """Converts the string mac address into a byte buffer."""
    mac = mac.replace(":", "").replace("-", "")
    return binascii.unhexlify(mac)


def inet_mactos(buffer: bytes, index: int, sep: str = ":") -> str:
    """Converts bytes to a MAC address."""
    return binascii.b2a_hex(buffer[index : index + 6], sep=sep).decode("utf-8")


def inet_stoip(ip_address: str) -> bytes:
    """Converts the string ip address into a byte buffer."""
    return inet_aton(ip_address)


def inet_iptos(buffer: bytes, offset: int) -> str:
    """Converts bytes to an IP address."""
    return inet_ntoa(buffer[offset : offset + 4])


def inet6_iptos(buffer: bytes, offset: int) -> str:
    """Converts bytes to an IP address."""
    return inet_ntop(AF_INET6, buffer[offset : offset + 16])


def inet6_stoip(ip6: str) -> bytes:
    """Converts the string ip address into a byte buffer."""
    return inet_pton(AF_INET6, ip6)


class EthernetHeader:
    """Small wrapper for raw ethernet message headers.

    The basic structure of this header is defined as follows:

    >>> +-------------------------------------------------+
    >>> | EthernetHeader                                  |
    >>> +---------------+--------------+------------------+
    >>> | dest: byte[6] | src: byte[6] | eth_type: uint16 |
    >>> +---------------+--------------+------------------+

    :param dest: The destination MAC address of this packet. Usually this field
                points to the multicast MAC address (``FF:FF:FF:FF:FF:FF``).
    :type dest: str

    :param src: the source MAC address for this packet
    :type src: str

    :param eth_type: The specified ethernet type for this packet. This value can
                    be used for validation, because it has to be ``0x8033``.
    :type eth_type: uint16 (int)
    """

    def __init__(self, buf: bytes = None) -> None:
        self.dest: str = "FF:FF:FF:FF:FF:FF"
        self.src: str = ""
        self.eth_type: int = 0x8033
        if buf is not None and len(buf) >= 14:
            self.dest = inet_mactos(buf, 0)
            self.src = inet_mactos(buf, 6)
            self.eth_type = struct.unpack("!H", buf[12:14])[0]

    def __bytes__(self) -> bytes:
        """Packs this header object into a byte buffer.

        The returned structure is defined in the documentation of this class.

        :returns: all values stored by this header object packed into a byte buffer.
        """
        buf = bytearray()
        buf += inet_stomac(self.dest)
        buf += inet_stomac(self.src)
        buf += struct.pack("!H", self.eth_type)
        return bytes(buf)


class SADPHeader:
    """A simple class wrapper to store header variables of SADPPackets."""

    def __init__(self, buf: bytes = None) -> None:
        self.prefix: int = 0  #  uint8
        self.counter: int = 0  # uint32
        self.packet_type: int = 0  # uint8
        self.params: int = 0  # uint8
        self.checksum: int = 0  # uint16
        if buf is not None and len(buf) >= 14:
            values = struct.unpack("!HBBIHBBH", buf)
            self.prefix = values[2]
            self.counter = values[3]
            self.packet_type = values[5]
            self.params = values[6]
            self.checksum = values[7]

    def __bytes__(self) -> bytes:
        buf = bytearray(14)
        struct.pack_into(
            "!HBBIHBBH",
            buf,
            0,
            0x2102,
            0x01,
            self.prefix,
            self.counter,
            0x0604,
            self.packet_type,
            self.params,
            self.checksum,
        )
        return bytes(buf)


class SADPPayload:
    """The base class for all payload types."""

    def __init__(self, buf: bytes = None) -> None:
        self.buf = buf

    def __bytes__(self) -> bytes:
        raise NotImplementedError(
            "Abstract class SADPPayload does not implement __bytes__()"
        )


class SADPPacket:
    """A dynamic class for creating SADPPackets for sending and resceiving data."""

    def __init__(self, buf: bytes = None) -> None:
        self.eth_header: EthernetHeader = EthernetHeader(buf[:14] if buf else None)
        self.header: SADPHeader = SADPHeader(buf[14:] if buf else None)
        self.src_ip: str = ""
        self.dest_ip: str = "0.0.0.0"
        self.subnet: str = "0.0.0.0"
        self.payload: SADPPayload = SADPPayload()
        if buf is not None and len(buf) >= 52:
            self.src_ip = inet_iptos(buf, 34)
            self.dest_ip = inet_iptos(buf, 44)
            self.subnet = inet_iptos(buf, 48)
            self.payload = SADPPayload()
            if self.header.packet_type in PAYLOAD_TYPE:
                # Create a payload object of type (class<? extends SADPPayload>)
                self.payload = PAYLOAD_TYPE[self.header.packet_type](buf[52:])

    def insert_checksum(self):
        """Calculates the checksum for this packet."""
        if self.header.checksum == 0:
            buf = to_uint16_buf(bytes(self)[14:], encoding=LITTLE_ENDIAN)
            self.header.checksum = get_checksum(buf, self.header.prefix) & 0xFFFF

    def __bytes__(self) -> bytes:
        buf = bytearray()
        buf += bytes(self.eth_header)
        buf += bytes(self.header)
        buf += inet_stomac(self.eth_header.src)
        buf += inet_stoip(self.src_ip)
        buf += inet_stomac(self.eth_header.dest)
        buf += inet_stoip(self.dest_ip)
        buf += inet_stoip(self.subnet)
        buf += bytes(self.payload)
        return bytes(buf)


def payload(ptype: int):
    """Simple class descriptor to register payload types

    Use this descriptor to define payload classes that are used within the
    parsing process of a ``SADPPacket``. Note that this method will raise
    a ``NameError`` if the payload type has already been assigned to another
    class.

    Example for registering a payload class for the `UpdateIP` packet type.

    >>> @payload(PACKET_TYPE['UpdateIP'])
    >>> class MySADPPayload(SADPPayload):
    ...    pass

    :param ptype: the packet type the payload class should be mapped to
    """

    def do_register(payload_type):
        if ptype in PAYLOAD_TYPE:
            raise NameError(f"Payload of type {ptype} already exists")
        PAYLOAD_TYPE[ptype] = payload_type
        return payload_type

    return do_register
