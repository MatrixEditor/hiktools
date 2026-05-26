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
Platform key registry for digicap.dav HK20/HK30 files.

After the outer XOR layer (see :data:`hiktools.fmod.digicap.DigiCap.KEY_XOR`),
newer firmware contains a second HK30 section encrypted with AES-256-ECB. The
256-bit AES key is derived from a 32-byte platform seed via :func:`gen_aes_key`
in :mod:`hiktools.fmod.crypto`. Each platform ships with two seeds, one for the
HK30 header and one for the embedded file payloads.

The seeds below come from publicly available extractor scripts and from the
``hikpack`` reference binary. Keys for newer platforms (device-id prefix 138 /
0x8A and above) are not currently public and must be recovered from a running
device.
"""

__all__ = [
    "PLATFORM_KEYS",
    "find_platform_key",
    "list_known_platforms",
]


PLATFORM_KEYS = {
    # R6 -- DS-2CD2x42 series and family. Hikpack v2.5 entry id=1.
    "R6": {
        "header": bytes.fromhex(
            "b64ec50866c49b757f1b2726a3755f22"
            "52abdfe9fbbb151e247d0d806ae425db"
        ),
        "file": bytes.fromhex(
            "bddc070b81fc4e47d03a7ed04c5b58d0"
            "72e7215d4ad4634754b2e5b68732bd37"
        ),
        "notes": "DS-2CD2x42 family, recovered from hikpack v2.5",
    },

    # Hikpack v2.5 entry id=2. Platform identity not yet correlated to a
    # specific device family. Provided for completeness so that older
    # firmware that fails R6/E3S can still be tried automatically.
    "hikpack_id2": {
        "header": bytes.fromhex(
            "603c7268b77d53005f05544dec4b7443"
            "96d903188e3d68bcb1a490fad9e88cc2"
        ),
        "file": bytes.fromhex(
            "234fc53e974aef14e6039d4ff08e2acc"
            "ebf0ea2c9135f91685295a781fe631d4"
        ),
        "notes": "Hikpack v2.5 entry id=2, family not yet identified",
    },

    # Platform 0x85, device-class 0x850000/0x850001 ("E3S_h2").
    # Same keys as published in HaToan/Decrypt-Firmware-Hikvision.
    "E3S_h2": {
        "header": bytes.fromhex(
            "e5bf668f7d8cdb8d381fab7977bb7276"
            "5d2d2ff2c9b4f71adec1f5743e42d08e"
        ),
        "file": bytes.fromhex(
            "918da7b326690e5271942d6ccd1cd682"
            "1dd925515e988dd40d9875f1dad0b13d"
        ),
        "notes": "device-class 0x850000 / 0x850001",
    },

    # Platform 0x85, device-class 0x850100/0x850101 ("E3S_alt").
    "E3S_alt": {
        "header": bytes.fromhex(
            "51e846d70b8e23dace1609463af2b2f1"
            "4a2157409f4931bd50e440ff76a60a4d"
        ),
        "file": bytes.fromhex(
            "81ecaeb20c6f8de0fde3d4afb4ace90a"
            "9cb0e59d19d3b7b70034a4243cf39754"
        ),
        "notes": "device-class 0x850100 / 0x850101",
    },
}


def find_platform_key(name: str) -> dict | None:
    """Return the seed pair for a platform name, or None if absent."""
    return PLATFORM_KEYS.get(name)


def list_known_platforms() -> list[str]:
    """Return the names of every registered platform."""
    return sorted(PLATFORM_KEYS.keys())
