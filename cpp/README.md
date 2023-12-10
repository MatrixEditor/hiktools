# Native C/++ SADP Library

_Note: This library is a work in progress. Program execution at your own risk;_ [API-Docs](https://matrixeditor.github.io/hiktools/).

## Network Interfaces ##

Before setting up a client or socket that can send or receive SADP packets,
the system's available network interfaces must be known. The namespace `eth::adapter` covers different utility methods and classes to query all network interfaces, for instance:

```{.cpp}
using namespace eth::adapter;

NetInterfaceList *list = GetNetInterfaces();
if (list) {
  for (int i = 0; i < list.size(); i++) {
    // The returned NetInterface stores information about the 
    // following attributes:
    //    - MAC address
    //    - Interface index
    //    - IPv6 address
    //    - Current IPv4 address
    //    - Interface name
    const NetInterface &ni = list.at(i);
  }
}
```

To refresh the list with its `NetInterface` objects, invoke the `ClearNetInterfaces()` method and query them again.

## API Functionalities

The `eth` namespace offers a fully implemented layer 2 socket to send and receive proprietary packets. These sockets should be created with the `NetInterface` to bind itself to it, which isn't necessary.

New sockets can be created rather easy, just declare a new variable:
```{.cpp} 
#include "sadplib.h"

eth::IISocket sock;
```

The declared socket has no use case, because it does not contain any real file descriptor to a raw socket. To create one, call the `Create` function:

```{.cpp}
eth::adapter::NetworkInterface &ni = ...;
if (sock.Create(&ni, 0x3380) < 0) {
  //report error
}
```

**Warning:** Custom protocol support is currently disabled, so layer 2 sockets will receive all packets. The `Daemon` class automatically filters the right packets out of the received ones.

**Important:** Before you create the raw socket, make sure you have the `NetworkInterface` instance. This will be used as a reference, so the socket knows where to bind to.

The created socket can be used for sending **only** - receiveing is not supported yet. To enable packet receiving, just call the `Bind`-method:

```{.cpp}
if (sock.Bind() < 0) {
  // report error
}
```
---

Next, we want to create proprietary SADP packets and send them to the link-local broadcast. By now, only inquiry packets can be generated automatically. However, if you want to create packets, take a look at the method documentation of `BuildFrame` provided in [sadplib.h](sadplib.h).

To create **and** send an inquiry-packet, there is a pre-defined method to simplify the creation process:
```{.cpp}
// This method will call BuildInquiry(), GetSize() and the 
// sock.Send(...) method.
eth::sadp::packet::SendInquiry(sock);
```

## SADPTool (currently)

By now, the `sadplib` can be used to communicate with Hikvision devices over the local area network via their Search Active Devices Protocol (SADP). Note that there is currently no possibility to run this small library without `sudo`. 

The [sadptool.cpp](sadptool.cpp) currently sends an Inquiry-Packet and waits for the next response. Further use-case implementation is in progress.

---
Below, the full example of how to use the c++ library:
```{.cpp}
#include "sadplib"

using namespace eth;

int main(void) {
  // Create a new socket;
  IISocket sock;

  // Creates the socket descriptor; Note that the interface 
  // can be queried by calling eth::adapter::GetNetInterfaces().
  if (sock.Create(&networkInterface, 0x3380) < 0) {
    // log error
    exit(1);
  }

  // To bind the socket in order to receive packets, use Bind()
  if (sock.Bind() < 0) {
    exit(1);
  }

  // To send a simple Inquiry-packet, there is a utility method,
  // that automatically builds and sends the packet.
  sadp::packet::SendInquiry(sock);

  // Receiving is rather simple, just call Receive() and the bytes 
  // that have been read are returned.
  const int bytes = sock.Receive();
  if (bytes < 0) {
    exit(1);
  }

  // The packet creation can be done by simply casting the received
  // bytes to the packet structure. Note that the receiving buffer 
  // will be cleared automatically when trying to receive the next
  // packet.
  const sadp::sadp_hdr *header = (const sadp::sadp_hdr *)sock.GetBuffer();
  
  // Check against the SADP identifier
  if (ntohns(header->h_proto) == 0x8033) {
    // Same as above: simply casting the payload pointer to the 
    // pre-defined sadp_frame structure.
    const sadp::sadp_frame *frame = (const sadp::sadp_frame *)header->payload;

    //handle packet...
  }
}
```