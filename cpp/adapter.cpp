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
#include <string>
#include <iostream>
#include <fstream>

#include <string.h>

#include "adapter.h"

//-----------------------------[NetInterface]-----------------------------

eth::adapter::NetInterface::NetInterface(
  const unsigned int _Index, const std::string &_Name,
  const std::string &_Mac, const std::string &_Inet6,
  const unsigned int _Flags
) : index{_Index}, scope{_Flags}
{
  this->mac = std::string(_Mac);
  this->ipv6 = std::string(_Inet6);
  this->name = std::string(_Name);

  const char *inet4 = eth::adapter::GetInet4Address(this->name);
  this->ipv4 = std::string(inet4);
}

const std::string &eth::adapter::NetInterface::GetIpv4Address() const 
{
  return this->ipv4;
}

const unsigned int eth::adapter::NetInterface::GetScope() const 
{
  return this->scope;
}

const unsigned int eth::adapter::NetInterface::GetInterfaceIndex() const 
{
  return this->index;
}

const std::string &eth::adapter::NetInterface::GetIpv6Address() const 
{
  return this->ipv6;
}

const std::string &eth::adapter::NetInterface::GetName() const 
{
  return this->name;
}

const std::string &eth::adapter::NetInterface::GetMacAddress() const 
{
  return this->mac;
}

inline const bool eth::adapter::NetInterface::IsCompat() const
{
  return (this->GetScope() & IP_ADDR_COMPAT) != 0;
}

inline const bool eth::adapter::NetInterface::IsGlobal() const
{
  return (this->GetScope() & IP_ADDR_GLOBAL) != 0;
}

inline const bool eth::adapter::NetInterface::IsLinkLocal() const
{
  return (this->GetScope() & IP_ADDR_LINKLOCAL) != 0;
}

inline const bool eth::adapter::NetInterface::IsLoopback() const
{
  return (this->GetScope() & IP_ADDR_LOOPBACK) != 0;
}

inline const bool eth::adapter::NetInterface::IsSiteLocal() const
{
  return (this->GetScope() & IP_ADDR_SITELOCAL) != 0;
}

//-----------------------------[NetInterface]-----------------------------

//---------------------------[NetInterfaceList]---------------------------

/**
 * @brief The file path to inet6 address values.
 */
static const char *IF_INET6_PATH = "/proc/net/if_inet6";

/**
 * @brief The basic path where files for every network interface are stored.
 */
static const char *NET_PATH = "/sys/class/net/";

/**
 * @brief THe global interface list 
 * 
 */
static eth::adapter::NetInterfaceList globalList;

void eth::adapter::ClearNetInterfaces() 
{
  if (globalList.size()) {
    globalList.clear();
  }
}

const eth::adapter::NetInterfaceList *eth::adapter::GetNetInterfaces() 
{
  if (globalList.size()) {
    return &globalList;
  }

  std::ifstream if_inet6, address;
  std::string ipv6, name, mac;
  unsigned int index, prefix, scope, flags;

  if_inet6.open(IF_INET6_PATH);
  // This way we indicate that an error has occurred.
  if (!if_inet6) {
    return &globalList;
  }

  do {
    if_inet6 >> ipv6;

    // NOTE: Here, we are testing against the EOF. It is necessary, 
    // because the last loop would read the last interface again. 
    // This check has to be done AFTER the first reading, otherwise 
    // the '\n' would be count as a valid character.
    if (if_inet6.eof()) {
      break;
    }

    if_inet6 >> std::hex >> index;
    if_inet6 >> std::hex >> prefix;
    if_inet6 >> std::hex >> scope;
    if_inet6 >> std::hex >> flags;
    if_inet6 >> name;

    std::string path = NET_PATH + name + "/address";
    address.open(path);
    if (!address) {
      return &globalList;
    }

    address >> mac;
    eth::adapter::NetInterface *interface = new eth::adapter::NetInterface(
      index, name, mac, ipv6, scope
    );

    globalList.push_back(*interface);

    address.close();
  } while (if_inet6.peek() == '\n' && !if_inet6.eof());

  if_inet6.close();
  return &globalList;
}

//---------------------------[NetInterfaceList]---------------------------

// Most of the code was taken from here:
// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
const char *eth::adapter::GetInet4Address(const std::string &_Name)
{
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;

  strncpy(ifr.ifr_name , _Name.c_str(), IFNAMSIZ - 1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  return inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
}
