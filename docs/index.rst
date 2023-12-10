.. hiktools documentation master file, created by
   sphinx-quickstart on Mon Aug 15 18:25:18 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

hiktools' documentation!
====================================

.. toctree::
   :maxdepth: 1
   :caption: Developer Interface:

   sadp
   csadp
   fmod

Features
--------

- "Native" interface on sending and receiving SADP packets
- Client for XML based UDP communication on port 37020
- Generation of old reset code
- Hikvision firmware inspector and extractor
- Wireshark dissector written in Lua for Search Active Devices Protocol (SADP)
- Disassebled C/C++ code snippets for checksum algorithm and packet building


.. note::

   Previos versions of hiktools were unstable in terms of working with firmware
   files, but since 1.2.2 the while codebase has been refactored to be more robust.


Usage
-----

Installation
~~~~~~~~~~~~

.. code:: shell

   git clone https://github.com/MatrixEditor/hiktools.git
   cd hiktools/ && pip install .

Build the docs:
~~~~~~~~~~~~~~~

.. code:: shell

   cd docs/
   pip install -U sphinx
   sphinx-build -b html source build

Install dissector
~~~~~~~~~~~~~~~~~

Open up wireshark go to Help > About Wireshark > search for "Global Lua Plugins" and copy the location.

.. code:: shell

   $LOCATION="..."
   # on unix
   cp hiktools/lua/sadp.lua $LOCATION/sadp.lua
   # on windows
   copy "hiktools\lua\sadp.lua" "$LOCATION\sadp.lua"

Basic Usage
~~~~~~~~~~~

- Firmware inspection and extraction

.. code:: python

   from hiktools import fmod

   # Open the resource at the specified path (loading is done automatically)
   # or manually decrypt the firmware file.
   with fmod.DigiCap('filename.dav') as dcap:
      # Iterate over all files stored in the DigiCap object
      for file_info in dcap:
         print('> File name="%s", size=%d, pos=%d, checksum=%d' % file_info)

      # get file amount and current language
      print("Files: %d, Language: %d" % (dcap.head.files, dcap.head.language))

      # save all files stored in <filename.dav>
      fmod.export(dcap, "outdir/")

- Native interface on sending raw packets (only LINUX)

.. code:: python

   from hiktools import csadp

   # Because the following module requires root priviledges it has to be
   # imported directly
   from hiktools.csadp import CService

   sock = CService.l2socket('wlan0')
   counter = 2855

   # Building an inquiry packet
   packet = csadp.packet(
      'src_mac', 'src_ip', 0x03, counter,
      checksum=csadp.from_counter(counter),
      payload='\x00'*28
   )

   # If you want to have the packet as an object use parse()
   packet_obj = csadp.parse(packet)

   sock.send(packet) # or sock.send(bytes(packet_obj))
   response = csadp.parse(sock.recv(1024))


- Interact with the device through UDP broadcast

.. code:: python

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


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
