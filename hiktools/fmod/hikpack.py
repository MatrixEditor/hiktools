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
Platform key extractor for the ``hikpack`` reference binary.

Hikpack stores its platform key table as fixed-size records in ``.rodata``.
The record header is the literal ``78 00 00 00 <id> 00 00 00`` (entry size
0x78, little-endian platform id), followed by two 32-byte seeds (header then
file). The seeds themselves are high-entropy so the record header is the
reliable anchor.

When a newer ``hikpack`` binary appears in the wild, run :func:`extract_keys`
against it and merge the result into :data:`hiktools.fmod.keys.PLATFORM_KEYS`.
"""

__all__ = ["extract_keys", "iter_records"]

import re
from typing import Iterator


_RECORD_RE = re.compile(rb"\x78\x00\x00\x00[\x01-\x40]\x00\x00\x00", re.DOTALL)


def iter_records(blob: bytes) -> Iterator[tuple[int, int, bytes, bytes]]:
    """Yield (file_offset, platform_id, header_seed, file_seed) for each
    candidate record found in ``blob``. Records with low-entropy seeds are
    skipped to avoid matching zero-filled padding regions."""
    for match in _RECORD_RE.finditer(blob):
        off = match.start()
        pid = blob[off + 4]
        header_seed = blob[off + 8:off + 40]
        file_seed = blob[off + 40:off + 72]
        if len(header_seed) != 32 or len(file_seed) != 32:
            continue
        # entropy floor: a real seed has at least 16 distinct byte values
        if len(set(header_seed)) < 16 or len(set(file_seed)) < 16:
            continue
        yield off, pid, header_seed, file_seed


def extract_keys(path: str) -> dict[int, dict[str, bytes]]:
    """Parse a hikpack ELF and return a ``{platform_id: {header, file}}`` map.

    The mapping uses the integer platform id (1-based, as embedded in the
    binary) as the key. Cross-reference against a digicap.dav sample to learn
    which device family a numeric id corresponds to.
    """
    with open(path, "rb") as fh:
        blob = fh.read()

    out: dict[int, dict[str, bytes]] = {}
    for _, pid, header_seed, file_seed in iter_records(blob):
        out[pid] = {"header": header_seed, "file": file_seed}
    return out


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m hiktools.fmod.hikpack <hikpack-binary>")
        sys.exit(1)

    keys = extract_keys(sys.argv[1])
    if not keys:
        print(f"no platform key records found in {sys.argv[1]}")
        sys.exit(2)

    for pid in sorted(keys):
        seeds = keys[pid]
        print(f"platform id={pid}")
        print(f"  header: {seeds['header'].hex()}")
        print(f"  file:   {seeds['file'].hex()}")
