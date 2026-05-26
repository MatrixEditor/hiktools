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
AES-256-ECB layer for HK20/HK30 digicap.dav files.

The platform AES key is derived from a 32-byte platform seed using
:func:`gen_aes_key`, a per-byte permutation embedded in the on-device
``daemon_fsp_app`` binary and in vendor packing tools. The function is fully
invertible so given a key, the seed can be recovered; in practice the seeds
are what is stored and the key is computed on the fly.

The set of HK30 filenames in :data:`KNOWN_FILE_NAMES` is used as a plaintext
oracle to decide whether a candidate platform key has decrypted a section
correctly.
"""

__all__ = [
    "gen_aes_key",
    "decrypt_aes_ecb",
    "try_platform_keys",
    "KNOWN_FILE_NAMES",
]

from typing import Iterable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from hiktools.fmod.keys import PLATFORM_KEYS


# A non-exhaustive set of file names that appear in HK30 file tables across
# Hikvision IPC and NVR firmware. Decrypting the table with the correct
# platform key always produces at least one of these strings in cleartext.
KNOWN_FILE_NAMES: tuple[bytes, ...] = (
    b"hroot.img",
    b"basebin",
    b"WebUI",
    b"webui",
    b"LiteOS",
    b"db.jffs2",
    b"ipc_db",
    b"_cfgUpgClass",
    b"_cfgUpgSecPls",
    b"dsp.img",
    b"logo.img",
    b"baseparam",
    b"davinci",
    b"uImage",
    b"rootfs",
    b"config",
    b"kernel",
    b"system.img",
    b"user.img",
    b"romfs",
    b"cramfs",
    b"digicap",
    b"dvrboot",
    b"hImage",
    b"hModule",
)


def gen_aes_key(seed: bytes, length: int = 32) -> bytes:
    """Derive a 32-byte AES-256 key from a 32-byte platform seed.

    Mirrors the routine compiled into ``hikpack`` and ``daemon_fsp_app``.
    The transform is per-byte and depends only on the byte value, its index,
    and the seed length, so a corrupt or partial seed cannot accidentally
    decrypt unrelated material.

    :param seed: 32-byte platform seed.
    :param length: seed/key length, must be 32 for AES-256.
    :return: 32-byte derived key, ready for :class:`AES` ECB use.
    """
    if len(seed) != length:
        raise ValueError(f"Seed must be exactly {length} bytes, got {len(seed)}")

    out = bytearray(length)
    for i in range(length):
        ch = seed[i]
        v = (
            ((i * i) & 0xFF)
            + ((ch * ch) & 0xFF)
            + ((ch % length) & 0xFF)
            + ((ch * length * i) & 0xFF)
        )
        out[i] = (v & 0xFF) ^ ch
    return bytes(out)


def decrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    """AES-256-ECB decrypt. Pads to a 16-byte boundary with NULs if needed."""
    if len(data) % 16 != 0:
        data = data + b"\x00" * (16 - len(data) % 16)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.decryptor().update(data) + cipher.decryptor().finalize()


def try_platform_keys(
    section: bytes,
    candidates: Iterable[str] | None = None,
    role: str = "header",
) -> tuple[str | None, bytes]:
    """Try every registered platform key against an HK30 section.

    A key is considered correct when the decrypted section contains at least
    one of :data:`KNOWN_FILE_NAMES`. The first matching platform wins; the
    decrypted bytes are returned so the caller can parse the file table.

    :param section: ciphertext (raw bytes from the HK30 body).
    :param candidates: optional iterable of platform names to try in order.
        If None, every key in :data:`PLATFORM_KEYS` is tried.
    :param role: either ``"header"`` or ``"file"`` to pick which seed in
        each platform entry to derive from.
    :return: (platform_name, plaintext) on success or (None, b"") on failure.
    """
    names = list(candidates) if candidates is not None else list(PLATFORM_KEYS.keys())
    for name in names:
        seeds = PLATFORM_KEYS.get(name)
        if not seeds or role not in seeds:
            continue
        key = gen_aes_key(seeds[role])
        plain = decrypt_aes_ecb(section, key)
        if any(fname in plain for fname in KNOWN_FILE_NAMES):
            return name, plain
    return None, b""
