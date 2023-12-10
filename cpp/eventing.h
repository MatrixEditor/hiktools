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
#if !defined(__EVENTING_H__)
#define __EVENTING_H__

#include "adapter.h"
#include "ethernet.h"

namespace eth
{
  
namespace event
{

/**
 * @brief Simple Event-Object that stores the received message.
 */
class PacketEvent 
{
  private:
    /**
     * @brief The received pacekt header
     */
    const eth::sadp::sadp_hdr *header;

    /**
     * @brief The received message without ethernet header
     */
    const eth::sadp::sadp_frame *frame;

    /**
     * @brief The socket that captured the packet
     */
    const eth::IISocket *sock;

  public:

    PacketEvent(
      const eth::sadp::sadp_hdr     *_Hdr,
      const eth::sadp::sadp_frame   *_Frame,
      const eth::IISocket           *_Socket
    ) : header{_Hdr}, frame{_Frame}, sock{_Socket} {};

    inline const eth::sadp::sadp_hdr *GetHeader() const
      { return header; }
    
    inline const eth::sadp::sadp_frame *GetSADPFrame() const
      { return frame; }

    inline const eth::IISocket *GetSocket() const
      { return sock; }

};

/**
 * @brief The main handler which should be registered to the sadp system.
 */
class PacketListener 
{
  public:
    virtual void onPacketReceived(
      const PacketEvent &
    ) const = 0;
};

using PacketListenerList = std::vector<const PacketListener *>;
  
} // namespace event

} // namespace eth

#endif // __EVENTING_H__
