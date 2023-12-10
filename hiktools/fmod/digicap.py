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
Decryption module of hikvision firmware files. Note that newer files aren't supported
yet as there is a new decryption key needed.

The basic process of decrpytion os the following:
    - Read the raw header (first 108 bytes)
    - Decode the header XOR with the decryption key
    - Parse the header
    - Decode the rest of the firmware file XOR with the decryption key
    - Parse the embedded files
"""
from __future__ import annotations

__all__ = [
    "InvalidFileFormatException",
    "FileAccessException",
    "DigiCapHeader",
    "read_raw_header",
    "decode_xor16",
    "split_header",
    "split_files",
    "fopen_dav",
    "DigiCap",
]

import logging

from io import IOBase
from typing import Generator, Iterator
from struct import unpack

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger("hiktools-logger")


###############################################################################
# Exception Classes
###############################################################################
class InvalidFileFormatException(Exception):
    """Base class for DAV file exceptions."""


class FileAccessException(Exception):
    """Base class for permission related issues."""


###############################################################################
# Data Types
###############################################################################
BIG_ENDIAN = ">"
LITTLE_ENDIAN = "<"


def uint32(value: bytes, encoding: str = LITTLE_ENDIAN) -> int:
    """Unpacks an unsigned 32-bit integer from the given buffer.

    :param value: the input buffer
    :type value: bytes
    :param encoding: the encoding to use, defaults to LITTLE_ENDIAN
    :type encoding: int, optional
    :raises TypeError: if the buffer is not a bytes object
    :return: the unpacked unsigned 32-bit integer
    :rtype: int
    """
    if isinstance(value, (bytes, bytearray, tuple, list)):
        if len(value) < 4:
            raise ValueError(
                "Could not verify buffer length - expected at least 4 "
                f"bytes, got {len(value)}"
            )

        (result,) = unpack(f"{encoding}I", bytearray(list(value)[:4]))
        return result

    raise TypeError(f"Unexpected input type: {type(value)}")


def uint24(value: bytes, encoding: int = LITTLE_ENDIAN) -> int:
    """Unpacks an unsigned 24-bit integer from the given buffer.

    :param value: the input buffer
    :type value: bytes
    :param encoding: the encoding to use, defaults to LITTLE_ENDIAN
    :type encoding: int, optional
    :raises ValueError: if an invalid encoding value is provided
    :raises TypeError: if the buffer is not a bytes object
    :return: the unpacked unsigned 24-bit integer
    :rtype: int
    """
    if isinstance(value, (bytes, bytearray, tuple, list)):
        if len(value) < 3:
            raise ValueError(
                f"Invalid buffer length ({len(value)}), expected at least 4 "
                "bytes to handle."
            )

        if encoding == BIG_ENDIAN:
            return value[0] << 16 | value[1] << 8 | value[2]
        if encoding == LITTLE_ENDIAN:
            return value[0] | value[1] << 8 | value[2] << 16

        raise ValueError(
            f"Unexpected Encoding, got {str(encoding)} ('<' or '>' accepted)"
        )
    raise TypeError(f"unexpected input type: {type(value)}")


def uint8(value: bytes | int) -> int:
    """Converts the input to an unsigned 8-bit integer

    :param value: the input buffer or int
    :type value: bytes
    :raises TypeError: if an invalid input is provided
    :return: the unsigned 8-bit integer
    :rtype: int
    """
    if isinstance(value, bytes):
        return int(value[0])
    if isinstance(value, int):
        return int(value & 0xFF)
    raise TypeError(f"unexpected input type: {type(value)}")


class DigiCapHeader:
    """A class covering important configuration information.

    :param magic: magic header bytes indicating the used firmware
    :type magic: int

    :param header_checksum: unused.
    :type header_checksum: int

    :param header_length: The header length is used to indicate the end of the filesystem index.
    :type header_length: int

    :param files: The amount of files stored in this firmware image.
    :type files: int

    :param language: The used language
    :type language: int

    :param device_class: unidentified
    :type device_class: int

    :param oem_code: maybe system verfication key
    :type oem_code: int

    :param signature: unidentified
    :type signature: int

    :param features: unidentified
    :type features: int

    """

    def __init__(
        self,
        magic: int = 0x00,
        header_checksum: int = 0x00,
        header_length: int = 0x00,
        files: int = 0x00,
        language: int = 0x00,
        device_class: int = 0x00,
        oem_code: int = 0x00,
        signature: int = 0x00,
        features: int = 0x00,
    ) -> None:
        self.magic = magic
        self.header_checksum = header_checksum
        self.header_length = header_length
        self.files = files
        self.language = language
        self.device_class = device_class
        self.oem_code = oem_code
        self.signature = signature
        self.features = features

    def __repr__(self) -> str:
        return f"<DigiCapHeader length={self.header_length}, files={self.files}>"


###############################################################################
# Funtions
###############################################################################
def fopen_dav(file_name: str, mode: str = "rb") -> IOBase:
    """Opens a file with te 'dav' extension.

    :param file_name:  The absolute or relative path to the file
    :type file_name: str
    :param mode: The mode this file shoul be opened with (either 'r' or 'rb'), defaults to 'rb'
    :type mode: str, optional

    :raises InvalidFileFormatException: on invalid file extension
    :raises ValueError: on invalid argument values
    :raises FileAccessException:  if there are issues with open the file

    :return: A file reader instance.
    :rtype: IOBase
    """
    if not file_name or not file_name.endswith("dav"):
        raise InvalidFileFormatException("Expected a *.dav file on input.")

    if not mode or mode not in ["r", "rb"]:
        raise ValueError("Expected a reading mode.")

    try:
        res = open(file_name, mode)  # noqa
    except OSError as open_error:
        raise FileAccessException(open_error) from open_error

    if not res:
        raise FileAccessException("Unable to open *.dav file")

    return res


def read_raw_header(resource: IOBase | str) -> bytes:
    """Reads the first 108 bytes from the resource stream."""
    if isinstance(resource, str):
        resource = fopen_dav(resource, "rb")

    if not resource or resource.mode != "rb":
        raise ValueError("Expected a reading bytes mode resource.")

    buf_len = 0x6C  # 108 bytes
    try:
        buf = resource.read(buf_len)
    except OSError as error:
        raise FileAccessException(error) from error

    return buf


def decode_xor16(buf: bytes, key: bytes, length: int) -> bytes:
    """Decodes (XOR) the given buf with a key."""
    result = bytearray()

    if length > 0 or len(key) != 0xF:
        for index in range(length):
            key_byte = key[index + (index >> 4) & 0xF]
            result.append(key_byte ^ buf[index])

    return bytes(result)


def split_header(buf: bytes) -> DigiCapHeader:
    """Extracts information from the decoded firmware header."""
    if not buf or len(buf) == 0:
        raise ValueError("Invalid buf object len() == 0 or object is None.")

    # REVISION: maybe add magic value check to validate the right firmware
    # file is going to be inspected.
    magic = uint32(buf[:4])  # 9 the buffer should have only four bytes
    header_checksum = uint32(buf[4:8])
    header_length = uint32(buf[8:12])
    files = uint32(buf[12:16])
    language = uint32(buf[16:20])
    device_class = uint32(buf[20:24])
    oem_code = uint32(buf[24:28])
    signature = uint32(buf[28:32])
    features = uint32(buf[32:36])

    checksum = uint8(buf[8]) + (uint24(buf[9:12]) * 0x100)
    if checksum != header_length:
        raise InvalidFileFormatException(
            f"Invalid header size: expected {checksum}, got {header_length}"
        )

    return DigiCapHeader(
        magic,
        header_checksum,
        header_length,
        files,
        language,
        device_class,
        oem_code,
        signature,
        features,
    )


def split_files(
    buf: bytes | IOBase, length: int = 0x40
) -> Generator[tuple, None, None]:
    """Iterates over all files located in the given filesystem index

    :param buf: the input buffer or file pointer
    :type buf: bytes
    :param length: the amount of bytes to read, defaults to 0x40
    :type length: int, optional
    :raises ValueError: if the reading mode is not 'rb'
    :raises ValueError: if the amount of bytes to read is <= 0
    :yield: a tuple storing the file name, file position, and file checksum
    :rtype: Generator[tuple, None, None]
    """
    if isinstance(buf, IOBase):
        if not buf or buf.mode != "rb":
            raise ValueError("Expected a reading bytes mode resource.")

        if length <= 0:
            raise ValueError("Expected a length > 0.")

        buf.seek(0, 0)
        buf = buf.read(length)

    index = 0x40
    amount = uint32(buf[12:16])
    for _ in range(amount):
        file_name = buf[index : index + 32].replace(b"\x00", b"")
        index += 32

        file_length = uint32(buf[index : index + 4])
        file_pos = uint32(buf[index + 4 : index + 8])
        file_checksum = uint32(buf[index + 8 : index + 12])
        index += 12
        yield file_name.decode("utf-8"), file_length, file_pos, file_checksum


###############################################################################
# Classes
###############################################################################
class DigiCap:
    """The base class for operating with digicap.dav files."""

    KEY_XOR = b"\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE"
    """The key used to encrypt/decrypt the firmware files."""

    def __init__(self, resource: str | IOBase = None) -> None:
        self._file = None
        self._name = None
        self._filelist = []
        self._len = 0
        self._head = None

        if resource is not None:
            if isinstance(resource, str):
                if not self.fopen(resource):
                    raise InvalidFileFormatException(f"Invalid input file: {resource}")

            elif isinstance(resource, IOBase):
                self._file = resource
                self._name = resource.name
            else:
                raise ValueError(f"Invalid argument type: {type(resource)}")

    def fopen(self, resource: str) -> bool:
        """Opens the given resource.

        Will be called automatically when this class is used in a with statement.
        """
        if resource is not None:
            self._file = fopen_dav(resource)
            self._name = resource
        return resource is not None

    def fclose(self):
        """Closes the current file reader.

        Will be called automatically when this class is used in a with statement.
        """
        self._file.close()

    def reset(self) -> bool:
        """Sets the reader's position to the start of the stream."""
        self._file.seek(0, 0)
        return self._file.seekable()

    def fread(self, length: int, offset: int = -1) -> bytes:
        """Reads the given amount of bytes from the underlying stream."""
        if self._file.closed:
            raise ValueError("FileInoutStream is closed!")

        if offset >= 0:
            self._file.seek(offset)
        return self._file.read(length)

    def fparse(self):
        """Parses the firmware file."""
        if self._file is not None:
            raw_head = read_raw_header(self._file)
            decoded_head = decode_xor16(raw_head, self.KEY_XOR, 0x6C)

            self._head = split_header(decoded_head)
            self.reset()
            raw_data = decode_xor16(
                self._file.read(self.head.header_length),
                self.KEY_XOR,
                self.head.header_length,
            )
            self._filelist = list(split_files(raw_data))
            if len(self) == 0:
                logger.warning("Could not decode firmware - detected 0 files!")
        else:
            raise ValueError("Input source is None.")

    @property
    def name(self) -> str:
        """The file name (absolute or relative)"""
        return self._name

    @property
    def head(self) -> DigiCapHeader:
        """The header object storing important configuration data."""
        return self._head

    def __enter__(self) -> "DigiCap":
        self.fparse()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.fclose()

    def __len__(self) -> int:
        return len(self._filelist) if not self._len else self._len

    def __iter__(self) -> Iterator[tuple]:
        return iter(self._filelist)

    def __getitem__(self, index: int) -> tuple:
        return self._filelist[index]

    def __repr__(self) -> str:
        return f'<DigiCap file="{self._name}">'
