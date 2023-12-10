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
Known payload implementations.
"""

__all__ = ["InquiryPayload", "inquiry", "InquiryResponsePayload"]

from hiktools.csadp.model import (
    SADPPayload,
    SADPPacket,
    payload,
    inet6_iptos,
    inet6_stoip,
    CLIENT_PREFIX,
    PACKET_TYPE,
)


@payload(PACKET_TYPE["Inquiry"])
class InquiryPayload(SADPPayload):
    def __init__(self, ipv6: str = None, buf: bytes = None) -> None:
        super().__init__(buf)
        self.ipaddress = ipv6
        if self.buf is not None:
            self.ipaddress = inet6_iptos(self.buf, 0)

    def __bytes__(self) -> bytes:
        if self.buf is None:
            self.buf = bytearray()
            self.buf += inet6_stoip(self.ipaddress)
            self.buf += bytes([0 for _ in range(12)])
            self.buf = bytes(self.buf)
        return self.buf


@payload(PACKET_TYPE["InquiryResponse"])
class InquiryResponsePayload(SADPPayload):
    pass


def inquiry(mac: str, ipv4: str, ipv6: str, counter: int) -> SADPPacket:
    packet = SADPPacket()
    packet.eth_header.src = mac
    packet.header.packet_type = PACKET_TYPE["Inquiry"]
    packet.header.counter = counter
    packet.header.prefix = CLIENT_PREFIX
    packet.src_ip = ipv4
    packet.payload = InquiryPayload(ipv6=ipv6)
    return packet
