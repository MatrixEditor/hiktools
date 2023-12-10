# Hiktools

![Module](https://img.shields.io:/static/v1?label=Module&message=hiktools&color=9cf)
![Build](https://img.shields.io:/static/v1?label=Python&message=>=3.5&color=green)
![Platform](https://img.shields.io:/static/v1?label=Platforms&message=Linux|Windows&color=yellowgreen)
![PyPi](https://img.shields.io:/static/v1?label=PyPi&message=1.2.2&color=green)


This respository was former known as `hikvision-sdk-cam`, but has changed since the old content of this repository was deleted. This is now a small project with four main functionalities:
* A Wireshark dissector for the Search Active Devices Protocol,
* Decrypt and extract hikvision firmware,
* Send raw SADP packets (only Linux) and
* Send commands via UDP Broadcast.

To get familiar with the API provided in this repository, take a quick look at the python documentation available **[here »](https://hiktools.readthedocs.io/)** or the
C++ documentation available at Github-Pages **[here »](https://matrixeditor.github.io/hiktools/docs/html/d3/dcc/md__r_e_a_d_m_e.html)**.

### Installation

You can now install the `hiktools` module with pip:

```bash
$ python3 -m pip install hiktools
```

### Overview
---
**Update:** Since feature version `1.1.0` the native packet creation and communication works! It is still only usable on UNIX systems that support sending raw ethernet frames. The checksum algorithm was disassebled and decompiled correctly, just the input parameters were interpreted wrong. The algorithm is implemented in [C/C++](/cpp/checksum.h) and [python3](/hiktools/csadp/checksum.py).

Communication on UDP works fine at the moment - this API is just a small wrapper which can be used for a more general API.

Firmware decryption and extraction will only work on newer `digicap.dav` files with at least  `1` file entry (otherwise there will be no files to inspect) in the header. All firmware files and updates can be downloaded from the following endpoint (EU):

* https://www.hikvisioneurope.com/uk/portal

There is also a full list of files available at this enpoint stored in a JSON file named [firmwarelist.json](/gists/firmwarelist.json).

> Info: There is an interesting file located in the extracted files of a firmware image: /hroot.img/initrd/etc/passwd. A password is set to the root user:

    Name: passwd
    Folder: -
    Size: 44
    Packed Size: 1 024
    Mode: -rwxrwxr-x
    Last change: 2016-12-23 08:27:46
    Last modification: 2016-12-23 08:27:46
    -------------------------------------------

    root:ToCOv8qxP13qs:0:0:root:/root/:/bin/psh

The plain password is `hiklinux`, kudos to [Don Bowman](https://blog.donbowman.ca/2018/01/18/hacking-the-hikvision-part-1/).

> Old exploit with authkey := YWRtaW46MTEK

### Basic Usage
---

- Firmware inspection and extraction

```python
from hiktools import fmod

# Open the resource at the specified path (loading is done automatically)
# or manually decrypt the firmware file (see documentation for actual code).
with fmod.DigiCap('filename.dav') as dcap:
  # Iterate over all files stored in the DigiCap object
  for file_info in dcap:
      print('> File name="%s", size=%d, pos=%d, checksum=%d' % file_info)

  # get file amount and current language
  print("Files: %d, Language: %d" % (dcap.head.files, dcap.head.language))

  # save all files stored in <filename.dav>
  fmod.export(dcap, "outdir/")
```

Or you can use the module main script to extract the files via the CLI:
```console
python3 -m hiktools.fmod input.dav outputDir
```

- Native interface on sending raw packets (only LINUX)
```python
from hiktools import csadp

# Because the following module requires root priviledges it
# has to be imported directly.
from hiktools.csadp import CService

sock = CService.l2socket('wlan0')
counter = 0x115e

# To build an Inquiry packet, we need the following information:
# - our mac, ipv4 and ipv6 address (and the counter of course)
packet = csadp.inquiry('<MAC>', '<IPv4>', '<IPv6>', counter)

# before we can send the message, a checksum has to be calculated
packet.insert_checksum()

sock.send(bytes(packet))
response = csadp.SADPPacket(sock.recv(1024))

# to view the contents just print the str() version
print(str(response))
```

- Interact with the device through UDP broadcast
```python
from hiktools import sadp
from uuid import uuid4

# create a packet from a simple dict object
inquiry = sadp.fromdict({
  'Uuid': str(uuid4()).upper(),
  'MAC': 'ff-ff-ff-ff-ff-ff',
  'Types': 'inquiry'
})

# Open up a client to communicate over broadcast
with sadp.SADPClient() as client:
  # send the inquiry packet
  client.write(inquiry)

  # iterate over all received packets (None is returned on error)
  for response in client:
    if response is None: break
    # initiate the response
    message = sadp.unmarshal(response.toxml())

    # message objects contain a dict-like implementation
    for property_name in message:
      print(message[property_name])

    # e.g.
    print('Device at', message['IPv4Address'])
```
