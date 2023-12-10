// The MIT License (MIT)

// Copyright (c) 2023 MatrixEditor

//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
#ifdef __unix__ 

#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/types.h>

#include <string.h> // for strcpy

#include "ethernet.h"

//-------------------------------[Counter]-------------------------------

static eth::Counter counter;

eth::Counter &eth::GetCounter() 
{
  return counter;
}

eth::Counter::Counter() 
{
  this->num = static_cast<unsigned int>(std::rand());
}

eth::Counter::Counter(unsigned int _Start)
  : num{_Start} {}

const unsigned int eth::Counter::Get() const
{
  return this->num;
}

void eth::Counter::Increment() 
{
  this->num = (unsigned int) (num + 1);
}

void eth::Counter::Set(const unsigned int _NewValue)
{
  this->num = _NewValue;
}

const unsigned int eth::Counter::GetAndIncrement() 
{
  const unsigned int count = this->num;
  this->Increment();
  return count;
}

//-------------------------------[ip]-------------------------------

static inline uint8_t IntFromHex(const uint8_t byte)
{
  if (byte >= '0' && byte <= '9') return byte - '0';
  else if (byte >= 'a' && byte <='f') return byte - 'a' + 10;
  else if (byte >= 'A' && byte <='F') return byte - 'A' + 10;
  return byte;
}

static inline uint8_t HexFromInt(const uint8_t _Src)
{
  if (_Src >= 0 && _Src <= 9) return _Src + '0';
  else if (_Src >= 0xA && _Src <=0xF) return _Src + 'a' - 10;
  return _Src;
}

void eth::ip::ToString(const uint32_t *_IpAddress, char *_DstAddress)
{
  uint8_t* ip = (uint8_t *)_IpAddress;

  char result[16] {0};
  sprintf(result, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  
  strcpy(_DstAddress, result);
}

void eth::ip::ToBytes(const char *_IpAddress, uint32_t *_DstAddress)
{
  struct in_addr ip_addr;
  inet_aton(_IpAddress, &ip_addr);

  *_DstAddress = (uint32_t) ip_addr.s_addr;
}

void eth::ip::ToString(const uint8_t *_Ip6Address, uint8_t *_DstAddress)
{  
  uint8_t *dst = _DstAddress;
  for (size_t i = 0; i < 16; i++) {
    unsigned char c0 = HexFromInt(_Ip6Address[i] >> 4);
    unsigned char c1 = HexFromInt(_Ip6Address[i] & 0xF);

    *(dst) = c0;
    *(dst + 1) = c1;
    dst +=2;
  }
}

void eth::ip::ToBytes(const uint8_t *_Ip6Address, uint8_t *_DstAddress)
{
  unsigned char *dst = _DstAddress;
  for (size_t i = 0; i < 32; i+=2) {
    unsigned char c = IntFromHex(_Ip6Address[i]);
    unsigned char c1 = IntFromHex(_Ip6Address[i + 1]);

    *(dst) = c << 4 | c1 & 0xFF;
    dst++;
  }
}

//-------------------------------[mac]-------------------------------

void eth::mac::ToString(const uint8_t *_MacAddress, uint8_t *_DstAddress)
{
  uint8_t *dst = _DstAddress;
  for (size_t i = 0; i < 6; i++) {
    unsigned char c0 = HexFromInt(_MacAddress[i] >> 4);
    unsigned char c1 = HexFromInt(_MacAddress[i] & 0xF);

    *(dst) = c0;
    *(dst + 1) = c1;
    if (i == 5) break;
    
    *(dst + 2) = ':';
    dst += 3;
  }
}

void eth::mac::ToBytes(const uint8_t *_MacAddress, uint8_t *_DstAddress)
{
  uint8_t *dst = _DstAddress;
  for (size_t i = 0; i < 18; i+=3) {
    unsigned char c = IntFromHex(_MacAddress[i]);
    unsigned char c1 = IntFromHex(_MacAddress[i + 1]);

    *(dst) = c << 4 | c1 & 0xF;
    dst++;
  }
}

//-------------------------------[IISocket]-------------------------------

eth::IISocket::IISocket() 
  : closed{false}, protocol{ETH_P_ALL}, interface{nullptr} {}

eth::IISocket::IISocket(const eth::adapter::NetInterface *_Interface)
  : IISocket() 
{
  this->interface = _Interface;
  if (interface) {
    if (this->Create(interface, protocol)) {
      this->Bind();
    }
  }
}

eth::IISocket::~IISocket()
{
  this->Close();
}

const bool eth::IISocket::Create(const eth::adapter::NetInterface *_Interface)
{
  return this->Create(_Interface, ETH_P_ALL);
}

const bool eth::IISocket::Create(
  const eth::adapter::NetInterface *_Interface, const uint16_t _Proto
) {
  if (this->interface != _Interface && _Interface) {
    this->interface = _Interface;
  }

  if (!this->interface) return false;

  if (this->protocol != _Proto) {
    this->protocol = _Proto;
  }

  this->sock = socket(AF_PACKET, SOCK_RAW, htons(this->protocol));
  this->closed = false;

  struct ifreq eth;
  ioctl(this->sock, SIOCGIFFLAGS, &eth);
 
  eth.ifr_flags |= IFF_PROMISC;
 
  ioctl(this->sock, SIOCSIFFLAGS, &eth);

  return (this->sock != -1);
}

const bool eth::IISocket::Bind() 
{
  struct sockaddr_ll socketaddress;
  memset(&socketaddress, 0x00, sizeof(socketaddress));
  socketaddress.sll_family = AF_PACKET;
  socketaddress.sll_protocol = htons(ETH_P_ALL);
  socketaddress.sll_ifindex = interface->GetInterfaceIndex();
  return bind(this->sock, (struct sockaddr *)&socketaddress, sizeof(socketaddress)) >= 0;
}

const int eth::IISocket::Receive() 
{
  int bytecount;

  memset((void *)this->buf, 0x00, BUFFER_SIZE);
  int size =  recv(this->sock, this->buf, BUFFER_SIZE,0);
  if (size < 0) {
    perror("Unexpected return code");
  }
  return size;
}

void eth::IISocket::Close() 
{
  if (this->IsClosed()) {
    return;
  }

  if (this->sock != -1) {
    close(this->sock);
  }
  // Don't delete the NetInterface reference, because the pointer
  // points to an internal structure.
  this->interface = nullptr;
  closed = true;
}

const int eth::IISocket::Send(char *_Buf, const int _Length) const
{
  return (int)send(this->sock, _Buf, _Length, 0x00);
}

const bool eth::IISocket::IsClosed() const 
{
  return closed;
}

const eth::adapter::NetInterface *eth::IISocket::GetInterface() const
{
  return interface;
}

const char *eth::IISocket::GetBuffer() const 
{
  return buf;
}

//-------------------------------[sadp]-------------------------------

#define __case(name) \
  case ((uint8_t)eth::sadp::sadp_query_type::name): return #name;

const char *eth::sadp::QueryTypeToString(
  const unsigned char _QType, 
  const eth::sadp::sadp_packet_type _PType 
) {
  uint8_t qtype = _QType;
  if (_PType == eth::sadp::sadp_packet_type::Response) {
    qtype--;
  }

  switch (qtype) {
    __case(Inquiry)
    __case(DeviceOnlineRequest)
    __case(UpdateIP)
    __case(ResetPassword)
    __case(CMSInfo)
    __case(ModifyNetParam)

    default: return "Unknown";
  };
}

#undef __case

#endif // __unix__