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
__all__ = ["export"]

from pathlib import Path
from hiktools.fmod.digicap import DigiCap, FileAccessException


def export(dfile: DigiCap, location: str) -> bool:
    """Extracts all files stored in the given digicap file.

    HKWS payloads are written as read. HK20/HK30 payloads are decrypted with
    the file-payload AES key for the platform that decoded the HK30 header.
    Falls back to writing the raw bytes if no platform has been identified.
    """
    if location is None or dfile is None:
        raise ValueError("Input file or location is null")

    path = Path(location)
    try:
        path.mkdir(exist_ok=True)
    except OSError as error:
        raise FileAccessException(error) from error

    file_key = None
    if dfile.platform is not None:
        from hiktools.fmod.crypto import gen_aes_key, decrypt_aes_ecb
        from hiktools.fmod.keys import PLATFORM_KEYS
        seeds = PLATFORM_KEYS.get(dfile.platform)
        if seeds is not None:
            file_key = gen_aes_key(seeds["file"])

    for fname, flen, fpos, _ in dfile:
        try:
            payload = dfile.fread(flen, fpos)
            if file_key is not None:
                payload = decrypt_aes_ecb(payload, file_key)[:flen]
            with open(str(path / fname), "wb") as exp_file:
                exp_file.write(payload)
        except OSError as err:
            print(str(err))
            return False

    return True
