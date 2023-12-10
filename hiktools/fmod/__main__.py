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
import sys

from hiktools.fmod import DigiCap, export

if __name__ == '__main__':
    args = len(sys.argv)

    if args == 2 and sys.argv[1] == '-h':
        print(f'Usage: {__name__} <Input File> <Output DIR>')
        sys.exit(1)

    if args != 3:
        print('[-] Expected only 2 arguments (type -h for help).')
        sys.exit(1)

    with DigiCap(sys.argv[1]) as dcap:
        print("Got", dcap.head.files, "files to save!")
        export(dcap, sys.argv[2])
        for resource in dcap:
            print('> File name="%s", size=%d, pos=%d, checksum=%d' % resource)
