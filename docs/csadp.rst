.. _csadp:

Native Search Active Devices Protocol (CSADP)
=============================================

.. automodule:: hiktools.csadp

.. contents:: Table of Contents

**Note:** If you can't see any contents below, ReadTheDocs-build fails on this module. Please refer to the documented source code
instead.

Usage:

.. code:: python

  from hiktools import csadp

  # Because the following module requires root priviledges it 
  # has to be imported directly.
  from hiktools.csadp import CService

  sock = CService.l2socket('wlan0')
  counter = 0x115e

  # To build an Inquiry packet, we need the following information:
  # - our mac, ipv4 and ipv6 address (and the counter of course)
  packet = csadp.Inquiry('<MAC>', '<IPv4>', '<IPv6>', counter)
  
  # before we can send the message, a checksum has to be calculated
  packet.insert_checksum()

  sock.send(bytes(packet))
  response = csadp.SADPPacket(sock.recv(1024))

  # to view the contents just print the str() version
  print(str(response))

.. autofunction:: get_checksum

.. autofunction:: inet_stomac

.. autofunction:: inet_mactos

.. autofunction:: inet_iptos

.. autofunction:: inet_stoip

.. autofunction:: inet6_stoip

.. autofunction:: inet6_iptos

.. autofunction:: payload

.. autoclass:: EthernetHeader
  :members:

.. autoclass:: SADPHeader
  :members:

.. autoclass:: SADPPayload
  :members:

.. autoclass:: SADPPacket
  :members:

.. _hiktools: https://github.com/MatrixEditor/hiktools