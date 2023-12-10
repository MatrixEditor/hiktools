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

#if !defined(__ADAPTER_INFO_H__)
#define __ADAPTER_INFO_H__

#include <string>
#include <vector>

// These imports are needed to get the ipv4 address via a simple
// UDP socket on the NetInterface.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace eth
{
  
namespace adapter
{

#define IP_ADDR_GLOBAL 0x0000U
#define IP_ADDR_LOOPBACK 0x0010U
#define IP_ADDR_LINKLOCAL 0x0020U
#define IP_ADDR_SITELOCAL 0x0040U
#define IP_ADDR_COMPAT 0x0080U

/**
 * @brief A network interface.
 */
class NetInterface {
  private: 
    /**
     * @brief The scope of this interface.
     */
    const unsigned int scope;

    /**
     * @brief The interface index.
     */
    const unsigned int index;

    /**
     * @brief The MAC address.
     * 
     * The address can be found in every /sys/class/net/<NAME>/address
     * file in an interface directory.
     */
    std::string mac;

    /**
     * @brief The raw inet6 address used in Inquiry packets.
     */
    std::string ipv6;

    /**
     * @brief The interface name.
     */
    std::string name;

    /**
     * @brief The raw inet4 address used in Inquiry packets.
     */
    std::string ipv4;

  public:
    /**
     * @brief Construct a new NetInterface object.
     * 
     * @param _Index The interface index
     * @param _Name The name of this interface (copied)
     * @param _Mac The local mac address (copied)
     * @param _Inet6 The ipv6 address (copied)
     * @param _Flags The flags which will be converted into an
     *               enumeration object (Scope).
     */
    NetInterface(
      const unsigned int _Index, const std::string &_Name,
      const std::string &_Mac, const std::string &_Inet6,
      const unsigned int _Flags
    );

    const std::string &GetIpv4Address() const;

    /**
     * @brief Get the Scope of this interface.
     * 
     * @return [const unsigned int] the scope of this interface
     */
    const unsigned int GetScope() const;

    /**
     * @brief Get the Interface Index.
     * 
     * @return [const unsigned int] the index of this interface. 
     */
    const unsigned int GetInterfaceIndex() const;

    /**
     * @brief Get the Mac Address of this interface.
     * 
     * You should use the eth::mac::ToBytes() method to convert this
     * address to bytes.
     * 
     * @return [const char*] the mac address
     */
    const std::string &GetMacAddress() const;

    /**
     * @brief Get the Ipv6 Address of this interface.
     * 
     * @b Note: The returned string is not normalized. Use the 
     * eth::ip::ToString() method to convert the returned address
     * to a human readable address.
     * 
     * @return [const char*] the ipv6 address
     */
    const std::string &GetIpv6Address() const;

    /**
     * @brief Get the name of this interface.
     * 
     * @return [const char*] the interface name
     */
    const std::string &GetName() const;

    const bool IsLoopback() const;
    const bool IsLinkLocal() const;
    const bool IsCompat() const;
    const bool IsSiteLocal() const;
    const bool IsGlobal() const;

};

/**
 * @brief Get the Inet4Addres of the specified interface.
 * 
 * @param _Name the network interface name
 * @return [const char*] the ip address as a string
 */
const char *GetInet4Address(const std::string &_Name);

/**
 * @brief Simple type definition for a linked list that stores the
 *        platform's network interfaces.
 * 
 * This class overloads the '[]' operator so that the following code
 * example can be used to iterate over the list:
 * @code {.cpp}
 * NetInterfaceList *list = GetNetInterfaces();
 * for (unsigned int i = 0; i < list->GetSize(); i++) {
 *    const NetInterface &interface = list->Get(i);
 *    //or
 *    const NetInterface &interface = (*list)[i];
 * }
 * @endcode
 * 
 * @b Note: This class is designed to store the interfaces parsed from 
 * /sys/class/net/.* and /proc/net/if_inet6.
 */
using NetInterfaceList = std::vector<NetInterface>;

/**
 * @brief Tries to load all network interfaces and stores them in a vector.
 * 
 * @return [const NetInterfaceList*] the interface list
 */
const NetInterfaceList *GetNetInterfaces();

/**
 * @brief Clears the currently loaded network interfaces.
 */
void ClearNetInterfaces();

} // namespace adapter

} // namespace eth

#endif // __ADAPTER_INFO_H__
