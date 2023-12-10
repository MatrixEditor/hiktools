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

import struct

__all__ = ["LITTLE_ENDIAN", "BIG_ENDIAN", "UIntArray", "to_uint16_buf"]

LITTLE_ENDIAN = "<"
BIG_ENDIAN = ">"


class UIntArray(list):
    """Simple wrapper class for byte buffers."""

    def __init__(self, bytes_size: int) -> None:
        self.max = 1 << bytes_size * 8

    def __iadd__(self, __x: list) -> "UIntArray":
        for i, val in enumerate(__x):
            if self.max <= val:
                raise TypeError(
                    "Unsupported value (0 - %#x) at index %d" % (self.max - 1, i)
                )
        return super().__iadd__(__x)


def to_uint16_buf(buffer: bytes, encoding: str = BIG_ENDIAN) -> UIntArray:
    """Converts the given byte buffer into an unsigned 16-bit integer array.

    :param buffer: the raw bytes buffer
    :type buffer: bytes
    :param encoding: the encoding to use, defaults to BIG_ENDIAN
    :type encoding: str, optional
    :raises ValueError: if an invalid encoding is provided
    :raises ValueError: if an invalid input length is provided
    :return: the converted buffer
    :rtype: UIntArray
    """
    if 62 < ord(encoding) or 60 > ord(encoding):
        raise ValueError("Invalid encoding value")

    length = len(buffer)
    if length == 0:
        return buffer
    if length % 2 != 0:
        raise ValueError(f"Invalid input array length ({length})")

    seq = UIntArray(2)
    for i in range(0, len(buffer), 2):
        seq += struct.unpack(encoding + "H", bytes(buffer[i : i + 2]))
    return seq
