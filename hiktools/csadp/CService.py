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
`WARNING`: This module is usable only on linux systems.

A small module which ensures the right permissions are used to execute the
script base. It covers the creation of a layer 2 socket.
"""

__all__ = ["l2socket"]

import socket

from sys import platform

# Check if the program is running with root priviledges
if platform != "linux":
    raise OSError("Unsupported platform for layer II network operations!")
else:
    try:
        import os

        if os.getuid():
            raise PermissionError("This library requires super-user priviledges.")

    except AttributeError as exc:
        raise PermissionError("This library requires super-user priviledges.") from exc


def l2socket(interface: str) -> socket.socket:
    """Creates a layer II socket and binds it to the given interface."""
    if not interface:
        raise ValueError("Interface not specified")

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.settimeout(2)
    sock.bind((interface, 0))

    return sock
