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
Decryption module of hikvision firmware files.

Two on-disk formats are handled:

* HKWS / single-layer XOR (older 5.3.x and below). Decryption uses only the
  outer XOR key in :data:`DigiCap.KEY_XOR`.
* HK20 / HK30 (5.4.x and newer). After the same outer XOR layer there is a
  second HK30 section encrypted with AES-256-ECB. The platform key is looked
  up from :mod:`hiktools.fmod.keys` and the AES stage is performed by
  :mod:`hiktools.fmod.crypto`. If no registered platform key fits the sample,
  the file table is left empty and a warning is logged. Platforms newer than
  ``0x85`` (device-id prefix 138 and above) do not currently have public keys
  and must be recovered from a running device.

The basic process of decryption is the following:
    - Read the raw header (first 108 bytes)
    - Decode the header XOR with the decryption key
    - Parse the header
    - Decode the rest of the firmware file XOR with the decryption key
    - For HK20 files, locate the HK30 section and decrypt it with AES
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
        res = open(file_name, mode)  #:noqa
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

    # Outer-header magic values, as parsed by uint32 little-endian.
    # "HKWS" -> 0x53574B48, "02KH" -> 0x484B3230, "03KH" -> 0x484B3330.
    # HKWS firmware is single-layer XOR; HK20 firmware contains a second
    # HK30 AES section beyond the XOR layer.
    MAGIC_HKWS = 0x53574B48
    MAGIC_HK20 = 0x484B3230
    MAGIC_HK30 = 0x484B3330

    def fparse(self):
        """Parses the firmware file."""
        if self._file is None:
            raise ValueError("Input source is None.")

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
        self._platform = None

        if len(self) == 0 and self.head.magic == self.MAGIC_HK20:
            # HK20 outer header had no file entries inline -- the table
            # lives inside the AES-encrypted HK30 section that follows.
            self._fparse_hk30()

        if len(self) == 0:
            logger.warning("Could not decode firmware - detected 0 files!")

    def _fparse_hk30(self):
        """Locate and decrypt the HK30 section that follows an HK20 header."""
        # Lazy imports keep the XOR-only fast path import-light.
        from hiktools.fmod.crypto import decrypt_aes_ecb, gen_aes_key, KNOWN_FILE_NAMES
        from hiktools.fmod.keys import PLATFORM_KEYS

        h1_size = self.head.header_length

        self._file.seek(h1_size)
        h2_xor = self._file.read(16)
        if len(h2_xor) < 16:
            logger.warning("Truncated HK30 section, refusing to decode")
            return

        h2_head = decode_xor16(h2_xor, self.KEY_XOR, 16)
        h2_magic = uint32(h2_head[:4])
        if h2_magic != self.MAGIC_HK30:
            logger.warning("Expected HK30 marker after HK20 header, got 0x%08x", h2_magic)
            return

        h2_size = uint32(h2_head[8:12])
        h2_body = self._file.read(h2_size)
        if not h2_body:
            return

        for name, seeds in PLATFORM_KEYS.items():
            key = gen_aes_key(seeds["header"])
            plain = decrypt_aes_ecb(h2_body, key)
            if not any(fname in plain for fname in KNOWN_FILE_NAMES):
                continue

            self._platform = name
            logger.info("HK30 section decrypted with platform key %r", name)
            self._filelist = list(self._iter_hk30_entries(plain, h1_size))
            return

        logger.warning(
            "HK30 section present but no registered platform key fits; "
            "newer platforms may need keys recovered from a live device"
        )

    @staticmethod
    def _iter_hk30_entries(plain: bytes, h1_size: int):
        """Yield file-table entries from a decrypted HK30 body.

        Two layouts have been observed in the wild. Try the chenx6-style
        fixed offset first (0xF0 + 0x40 stride) and fall back to a string
        scan if that produces nothing useful.
        """
        entries = []
        for off in range(0xF0, len(plain) - 0x2C, 0x40):
            name_bytes = plain[off:off + 0x20]
            try:
                null = name_bytes.index(b"\x00")
            except ValueError:
                continue
            name = name_bytes[:null]
            if not name or not all(0x20 <= b <= 0x7E for b in name):
                continue
            offset = uint32(plain[off + 0x20:off + 0x24])
            length = uint32(plain[off + 0x24:off + 0x28])
            checksum = uint32(plain[off + 0x28:off + 0x2C])
            entries.append((name.decode("ascii"), length, offset + h1_size, checksum))

        if entries:
            yield from entries
            return

        # Fallback: locate known names in the plaintext and align to the
        # nearest 0x20 boundary to read the surrounding entry struct.
        from hiktools.fmod.crypto import KNOWN_FILE_NAMES
        seen = set()
        for needle in KNOWN_FILE_NAMES:
            pos = plain.find(needle)
            if pos < 0:
                continue
            entry_start = pos - (pos % 0x20)
            if entry_start + 0x2C > len(plain) or entry_start in seen:
                continue
            seen.add(entry_start)
            name_bytes = plain[entry_start:entry_start + 0x20].replace(b"\x00", b"")
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError:
                continue
            offset = uint32(plain[entry_start + 0x20:entry_start + 0x24])
            length = uint32(plain[entry_start + 0x24:entry_start + 0x28])
            checksum = uint32(plain[entry_start + 0x28:entry_start + 0x2C])
            yield name, length, offset + h1_size, checksum

    @property
    def name(self) -> str:
        """The file name (absolute or relative)"""
        return self._name

    @property
    def head(self) -> DigiCapHeader:
        """The header object storing important configuration data."""
        return self._head

    @property
    def platform(self) -> str | None:
        """Name of the platform key that decrypted the HK30 section, if any.

        ``None`` for HKWS firmware (no AES layer) and for HK20 firmware whose
        platform key is not registered in :mod:`hiktools.fmod.keys`.
        """
        return getattr(self, "_platform", None)

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
