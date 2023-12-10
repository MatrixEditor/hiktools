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
__all__ = ["get_checksum"]

from hiktools.csadp.uarray import UIntArray


def get_checksum(buf: UIntArray, prefix: int) -> int:
    """The SADP checksum algorithm implemented in python3.

    For a more accurate view on the algorithm, see the C++ source code on the
    `hiktools`_ repository on github.

    :param buf: an unsinged int16 array (can be created via a call to
                  ``to_uint16_buf()``)
    :param prefix: the sender's type specification. As defined in the C++
                  header file, ``0x42`` specifies a client and ``0xf6``
                  an server.
    """
    csum: int = 0
    lower: int = 0
    high: int = 0
    index: int = 0

    if 3 < (prefix & 0xFFFFFFFE):
        index = (prefix - 4 >> 2) + 1
        while index != 0:
            prefix -= 4
            lower += buf[0]
            high += buf[1]

            buf = buf[2:]
            index -= 1

    if 1 < prefix:
        csum = buf[0]
        buf = buf[1:]
        prefix -= 2

    csum += lower + high
    if prefix != 0:
        csum += buf[0] & 0xFF

    csum = (csum >> 16) + (csum & 0xFFFF)
    # NOTE: by adding 1 << 32 to the calculated checksum, a virtual
    # cast to an unsigned integer is performed. Because python has
    # no inbuild unsinged types, this cast has to be done before
    # returning the value.
    csum = (1 << 32) + ~((csum >> 16) + csum)
    return csum
