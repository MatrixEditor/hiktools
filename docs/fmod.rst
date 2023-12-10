.. _fmod:

Firmware modulation (fmod)
==========================

.. automodule:: hiktools.fmod

.. contents:: Table of Contents

Interface
~~~~~~~~~

.. autofunction:: hiktools.fmod.read_raw_header

.. autofunction:: hiktools.fmod.decode_xor16

.. autofunction:: hiktools.fmod.split_header

.. autofunction:: hiktools.fmod.split_files

.. autofunction:: hiktools.fmod.fopen_dav

.. autofunction:: hiktools.fmod.export


Classes
~~~~~~~

.. autoclass:: hiktools.fmod.DigiCap
  :members:

Usage:

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

.. autoclass:: hiktools.fmod.DigiCapHeader

Exceptions
~~~~~~~~~~

.. autoclass:: hiktools.fmod.InvalidFileFormatException

.. autoclass:: hiktools.fmod.FileAccessException