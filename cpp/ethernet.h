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

#if !defined(__LAYER_2_H__)
#define __LAYER_2_H__

#include "adapter.h"

namespace eth 
{

/**
 * @brief Defines the maximum buffer size for receiving tasks.
 * 
 * The max buffer size of the receiving character buffer.
 */
#define BUFFER_SIZE 8192

/**
 * @brief Counter class used to manage the internal counter and its 
 *        access.
 * 
 * A global instance of this class will be created at runtime with a random
 * generated number as its starting point. 
 */
class Counter {
  private: 
    /**
     * @brief the internal counter used to 'sign' the packets.
     */
    unsigned int num;

  public:
    /**
     * @brief Construct a new Counter object.
     * 
     * This object starts at value 0.
     */
    Counter();

    /**
     * @brief Construct a new counter with the given start value.
     * 
     * @param _Start the starting point
     */
    Counter(unsigned int _Start);

    /**
     * @brief Returns the current counter value.
     * 
     * @return [const unsigned int] the counter's value
     */
    const unsigned int Get() const;

    /**
     * @brief Get the And Increment the counter
     * 
     * @return [const unsigned int] the counter before the increment
     */
    const unsigned int GetAndIncrement();

    /**
     * @brief Increments this counter.
     */
    void Increment();

    /**
     * @brief Sets the new starting point.
     * 
     * @param _NewValue the new starting point.
     */
    void Set(const unsigned int _NewValue);
};

/**
 * @brief The global counter instance.
 */
Counter &GetCounter();

namespace sadp
{

/**
 * @brief A simple struct used to cast the received bytes into that
 *        structure.
 * 
 * This type definition can be used as follows:
 * 
 * @code {.c}
 *  IISocket socket = ...;
 *  //...
 *  if (socket.Receive() > 0) {
 *      psadp_hdr packet = (psadp_hdr)(socket.GetBuffer());
 *  }
 * @endcode
 * 
 * See IISocket for more usage details.
 */
typedef struct sadp_hdr {

  /**
   * @brief The packet's destination MAC address.
   */
  unsigned char h_dest[6];

  /**
   * @brief The packet's source MAC address.
   * 
   */
  unsigned char h_src[6];

  /**
   * @brief The packet's protocol.
   */
  uint16_t h_proto;

  /**
   * @brief The paylod of the packet that can be parsed.
   */
  char payload[];

} sadp_hdr, *psadp_hdr;

enum class sadp_query_type : unsigned char {
  /**
   * @brief ?
   */
  DeviceOnlineRequest = 0x02,

  /**
   * @brief Device location query
   */
  Inquiry = 0x03,

  /**
   * @brief ?
   */
  UpdateIP = 0x06,

  /**
   * @brief ?
   */
  ResetPassword = 0x0a,

  /**
   * @brief ?
   */
  CMSInfo = 0x0c,

  /**
   * @brief ?
   */
  ModifyNetParam = 0x10

};

enum class sadp_packet_type : unsigned char {
  /**
   * @brief Indicator for a response packet.
   */
  Response = 0x01,

  /**
   * @brief Indicator for a request packet.
   */
  Request = 0x02
};

/**
 * @brief Converts the given packet type to a string representation.
 * 
 * @param _QType the query type 
 * @param _PType the packet type
 * @return [const char*] the type name
 */
const char *QueryTypeToString(
  const unsigned char _QType, 
  const sadp_packet_type _PType
);


typedef struct sadp_frame {

  /**
   * @brief The default start value for a SADP packet. (0x21)
   */
  uint8_t f_prefix = 0x21U;

  /**
   * @brief The packet type (either request or response).
   * 
   * Defines 0x02 to be a request and 0x01 a response packet.
   */
  uint8_t f_packet_type;

  /**
   * @brief The header client type, which is defined in the 'checksum.h' file.
   * 
   * There are two possible values of this client type number.
   * 
   * 1. [0x42]: While inspecting the network traffic between an hikvision 
   * ip-camera and the SADPTool, there was this code value when the SADPTool 
   * had send a message.
   * 
   * 2. [0xf6]:  Assuming the code defined above defines clients as the sender, 
   * this code indicates that a server has built the received packet.
   * 
   * Note that the client type value will be in the first by of this short
   * variable.
   */
  uint16_t f_client_type;

  /**
   * @brief The checksum counter which is used to verify the packet.
   */
  uint32_t f_counter;
  
  /**
   * @brief A simple number used to support calculation of the checksum. 
   * 
   * In all received packets this number was equal to 0x0604.
   */
  uint16_t f_marker = 0x0604U;

  /**
   * @brief The actual packet type.
   * 
   * Use the #PacketTypeToString() method to get the string representation of
   * this value.
   */
  uint8_t f_type;

  /**
   * @brief The parameters used in connection with the actual packet 
   *        type.
   * 
   * Most likely, this value is going to be 0.
   */
  uint8_t f_parameters = 0x00;

  /**
   * @brief The calculated checksum of this frame.
   * 
   * This checksum is verified by the #Checksum() implementation by this 
   * library (and in sadp.dll).
   */
  uint16_t f_checksum;

  /**
   * @brief The source MAC address that is equal to sadp_hdr::h_src.
   */
  uint8_t f_src_mac[6];

  /**
   * @brief The source IP address.
   */
  uint32_t f_src_ip;

  /**
   * @brief The destination MAC address that is equal to sadp_hdr::h_dest.
   */
  uint8_t f_dest_mac[6];

  /**
   * @brief The destination ip address.
   * 
   * This IP address which will be 0.0.0.0 in most cases.
   */
  uint32_t f_dest_ip = 0x00;

  /**
   * @brief The used subnet mask.
   */
  uint16_t f_subnet_mask = 0x00;

  /**
   * @brief The sadp payload.
   */
  char payload[];

} sadp_frame, *psadp_frame;


typedef struct inquiry_payload {

  /**
   * @brief The inet6 address of the sender.
   */
  uint8_t f_inet6_address[16];

} inquiry_payload, *pinquiry_payload;

} // namespace sadp

/**
 * @brief Internal namespace to separate IP address conversion
 *        methods.
 */
namespace ip
{

#define IPV6_ADDR_LEN 16
#define IPV6_ADDR_STR_LEN (IPV6_ADDR_LEN*2)

/**
 * @brief Converts an ipv4 address to string.
 * 
 * @param _IpAddress the address as an uint32_t
 * @param _DstAddress the destination buffer
 */
void ToString(const uint32_t *_IpAddress, char *_DstAddress);

/**
 * @brief Converts an ipv6 address to string.
 * 
 * Returns all hex bytes of the given 16-length input address. The
 * returned address has a length of 32, for instance:
 * 
 *    - "fe80000000000000b0235af200027250"
 * 
 * @param _Ip6Address the address buffer
 * @param _DstAddress the destination buffer
 */
void ToString(const uint8_t *_Ip6Address, uint8_t *_DstAddress);

/**
 * @brief Converts an ipv4 address to a number.
 * 
 * The output buffer should have a length of 4.
 * 
 * @param _IpAddress the address buffer
 * @param _DstAddress the number destination
 */
void ToBytes(const char *_IpAddress, uint32_t *_DstAddress);

/**
 * @brief Converts an ipv6 to a byte buffer
 * 
 * The output buffer should have a length of 16 bytes.
 * 
 * @param _Ip6Address the address buffer
 * @param _DstAddress the destination buffer
 */
void ToBytes(const uint8_t *_Ip6Address, uint8_t *_DstAddress);
} // namespace ip

/**
 * @brief Internal namespace to separate MAC address conversion
 *        methods.
 */
namespace mac
{

/**
 * @brief Converts the MAC address to string.
 * 
 * This method expects a number array of length 6.
 * 
 * @param _MacAddress the address buffer
 * @param _DstAddress the destination buffer
 */
void ToString(const uint8_t *_MacAddress, uint8_t *_DstAddress);

/**
 * @brief Converts the MAC address to bytes.
 * 
 * The expected structure of the given MAC address would be the following:
 * 
 *    - "12:34:56:78:90:12"
 * 
 * @param _MacAddress the address buffer
 * @param _DstAddress the destination buffer
 */
void ToBytes(const uint8_t *_MacAddress, uint8_t *_DstAddress);
} // namespace mac


/**
 * @brief A layer 2 socket used to send and receive SADP packets.
 */
class IISocket {
  private:
    /**
     * @brief The socket used for receiving and sending data.
     * 
     * By creating an object of this class, this socket won't be initialized. That
     * can be done by calling the #Create() method.
     */
    int sock;

    /**
     * @brief The buffer used to receive data.
     * 
     * See the definition of BUFFER_SIZE for more information.
     */
    char buf[BUFFER_SIZE];

    /**
     * @brief Stores the interface this socket was bound to.
     * 
     * The binding interface.
     */
    const eth::adapter::NetInterface *interface;

    /**
     * @brief Specifies the protocol to listen to.
     * 
     * The protocol on layer 2.
     */
    uint16_t protocol;

    /**
     * @brief Simple variable to indicate whether this socket has been 
     *        closed.
     */
    bool closed;

  public:
    /**
     * @brief Construct a new empty IISocket object
     * 
     * Note that this constructor does not create the system socket.
     */
    IISocket();

    /**
     * @brief Construct a new IISocket object and creates the layer 2 
     *        socket.
     * 
     * @param _Interface the interface to bind to
     */
    IISocket(const eth::adapter::NetInterface *_Interface);

    /**
     * @brief Destroy the IISocket object.
     * 
     * This method will have no effects if this socket has been closed 
     * already.
     */
    ~IISocket();

    /**
     * @brief Creates a new layer 2 socket on the stored interface.
     * 
     * The code that should create the layer 2 socket could be the following
     * for all packets:
     * @code {.C}
     * this->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     * @endcode
     * 
     * If a specific socket for the SADP protocol should be created, the code
     * would be like this:
     * @code {.C}
     * this->socket = socket(AF_PACKET, SOCK_RAW, htons(0x8033));
     * @endcode
     * 
     * @param _Interface the interface name
     * @param _Proto the used protocol
     * @return true if the socket creation was successfull
     * @return false if no socket could be created
     */
    const bool Create(
      const eth::adapter::NetInterface *_Interface, 
      const uint16_t _Proto
    );

    /**
     * @brief Creates a new layer 2 socket on the stored interface.
     * 
     * The code that should create the layer 2 socket could be the following
     * for all packets:
     * @code {.C}
     * this->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     * @endcode 
     * 
     * @param _Interface the interface name
     * @return true if the socket creation was successfull
     * @return false if no socket could be created
     */
    const bool Create(const eth::adapter::NetInterface *_Interface);

    /**
     * @brief Tries to capture the next packet from wire.
     * 
     * @return [const int] the number of bytes received or -1 on failure
     */
    const int Receive();

    /**
     * @brief Binds this socket to the interface provided in #Create().
     * 
     * This method should be build on the following code:
     * @code {.C}
     * struct sockaddr_ll socketaddress;
     * memset(&socketaddress, 0x00, sizeof(socketaddress));
     * socketaddress.sll_family = AF_PACKET;
     * socketaddress.sll_protocol = htons(this->protocol);
     * socketaddress.sll_ifindex = interface->GetInterfaceIndex();
     * // bind the socket
     * bind(this->sock, (struct sockaddr *)&socketaddress, sizeof(socketaddress));
     * @endcode
     * 
     * 
     * @return true if the socket has been bound to the interface
     * @return false on failure
     */
    const bool Bind();

    /**
     * @brief Sends the given data.
     * 
     * This method will expand to the following code:
     * @code {.c}
     * return (int)send(this->sock, _Buf, _Length, 0x00);
     * @endcode
     * 
     * @param _Buf the data to be sent
     * @param _Length the data length
     * @return [const int] the amount of bytes that have been sent or
     *         -1 on failure.
     */
    const int Send(char *_Buf, const int _Length) const;

    /**
     * @brief Closes this socket and releases all system associated 
     *        resources with it.
     * 
     * The basic execution flow should be the following:
     * @code {.C}
     *    close(this->socket);
     *    free(this->buffer);
     *    free(this->interface);
     * @endcode
     * 
     * This method should not have any effect if this socket has already 
     * been closed.
     */
    void Close();

    /**
     * @brief Returns whether this socket has been closed.
     * 
     * @return true if the socket has been closed
     * @return false if the socket is active
     */
    const bool IsClosed() const;

    /**
     * @brief Get the Interface of this socket.
     * 
     * @return [const NetInterface &] the interface
     */
    const eth::adapter::NetInterface *GetInterface() const;

    /**
     * @brief Get the Buffer.
     * 
     * @return [const char*] the raw buffer 
     */
    const char *GetBuffer() const;
};

} // namespace eth

#endif // __LAYER_2_H__
