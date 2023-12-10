.. _sadp:

Search Active Devices Protocol (SADP)
=====================================

.. automodule:: hiktools.sadp

.. contents:: Table of Contents

Interface
~~~~~~~~~

.. autofunction:: hiktools.sadp.unmarshal

.. autofunction:: hiktools.sadp.hik_code

.. autofunction:: hiktools.sadp.fromdict

Classes
~~~~~~~

Client
------

.. autoclass:: hiktools.sadp.SADPClient

Example usage

.. code:: python

  from hiktools import sadp

  with sadp.SADPClient(timeout=3) as client:
    # send data with client.write
    client.write(some_message)

    # receive bytes with client.recv_next() or just iterate
    # over next SADPMessages:
    for message in client:
      if message is None: break
      # de-serialize message
      response = sadp.unmarshal(message)


Response Classes
----------------

.. autoclass:: hiktools.sadp.ActionResponse
  :members:

  .. autoattribute:: hiktools.sadp.ActionResponse.__msg__

.. autoclass:: hiktools.sadp.DiscoveryPacket

.. autoclass:: hiktools.sadp.SafeCode
  :members:

.. autoclass:: hiktools.sadp.DeviceSafeCodePacket
  :members: