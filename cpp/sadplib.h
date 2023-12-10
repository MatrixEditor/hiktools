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

#if !defined(__SADP_LIB_H__)
#define __SADP_LIB_H__

#include "ethernet.h"
#include "adapter.h"
#include "checksum.h"
#include "eventing.h"

#include <thread>

namespace eth {

namespace sadp 
{

namespace packet
{

/**
 * @brief Get the size of the given sadp packet.
 * 
 * @param _Hdr the frame to inspect
 * @return [const int]  the size or -1 on error
 */
const int GetSize(const eth::sadp::sadp_hdr *_Hdr) noexcept;

/**
 * @brief Builds and sends an inquiry packet.
 * 
 * @param _Socket the socket which should send the data
 * @return true if the packet has been sent successfully,
 * @return false otherwise
 */
const bool SendInquiry(const eth::IISocket &_Socket);

/**
 * @brief Builds an Inquiry packet and returns its size.
 * 
 * @param _Interface the NetInterface
 * @return [const int] the packet's size
 */
eth::sadp::sadp_hdr *BuildInquiry(
  const eth::adapter::NetInterface *_Interface
);

#define DEFAULT_FRAME_BODY_SIZE 38 // body
#define DEFAULT_FRAME_HDR_SIZE 14 // header
#define DEFAULT_FRAME_SIZE 512 // rest for payload
#define MIN_FRAME_SIZE 80 // the minimum packet size

/**
 * @brief Inserts the given attributes to the output buffer.
 * 
 * @param _Interface the network interface storing the IPv4, IPv6 and 
 *                   MAC address
 * @param _PacketType the packet type
 * @param _ClientType the client type 
 * @param _QueryType the request or response packet type
 * @param _Payload the payload pointer (data will be copied)
 * @return the created packet
 */
eth::sadp::sadp_hdr *BuildFrame(
  const eth::adapter::NetInterface   *_Interface,
  const eth::sadp::sadp_packet_type   _PacketType,
  const eth::sadp::sadp_query_type    _QueryType,
  const char                         *_Payload,
  const size_t                        _Payload_Length,

  const uint16_t                      _ClientType = CSADP_CLIENT_TYPE
) noexcept;

} // namespace packet

class Daemon {
  private:
    /**
     * @brief A variable indicating whether this daemon is active.
     */
    bool running;

    /**
     * @brief The layer 2 socket.
     */
    eth::IISocket &socket;

    std::thread worker;

    eth::event::PacketListenerList listenerList{};

  public:
    /**
     * @brief Construct a new Daemon.
     * 
     * This constructor uses an editable socket object, because it has to 
     * send and receive packets.
     * 
     * @param _Socket the socket for networking actions
     */
    Daemon(eth::IISocket &_Socket);

    /**
     * @brief Starts this daemon.
     * 
     * This method should start a loop that runs until the #Stop() method
     * is called. In addition to that, the sadp::Notify() method should be
     * called whenever a packet with the protocol defined in this->socket
     * is
     */
    void Start();

    /**
     * @brief Stops this daemon.
     * 
     * The method should stop the damon @b after the next packet is 
     * received.
     */
    void Stop();

    /**
     * @brief Returns whether this daemon is active.
     * 
     * @return true if the daemon is active,
     * @return false on a stopped daemon
     */
    const bool IsRunning() const;

    void Run() noexcept;

    /**
   * @brief Registers the given handler.
   * 
   * @param _Listener the handler to add
   * @return true if the handler could be added successfully;
   * @return false otherwise
   */
  const bool AddListener(const eth::event::PacketListener *_Listener);

/**
 * @brief Removes the given handler if it exists.
 * 
 * @param _Listener the handler to remove
 * @return true if the handler has been removed;
 * @return false otherwise
 */
const bool RemoveListener(const eth::event::PacketListener &_Listener);

};

} // namspace sadp

} // namspace eth

#endif // __SADP_LIB_H__
