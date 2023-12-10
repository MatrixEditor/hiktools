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
#include "sadplib.h"

#include <string.h>
#include <vector>
#include <iostream>

// #include <thread>
// std::thread daemonThread(&Start);

//--------------------------------------[sadp::packet]--------------------------------------

const int eth::sadp::packet::GetSize(
  const eth::sadp::sadp_hdr          *_Hdr) noexcept
{
  if (!_Hdr) {
    return -1;
  }

  int size = DEFAULT_FRAME_HDR_SIZE + DEFAULT_FRAME_BODY_SIZE;

  char *payload = ((eth::sadp::psadp_frame)_Hdr->payload)->payload;
  size += (sizeof(payload) / sizeof(char));

  return size > MIN_FRAME_SIZE ? size : MIN_FRAME_SIZE; 
}

const bool eth::sadp::packet::SendInquiry(
  const eth::IISocket                &_Socket) 
{
  eth::sadp::psadp_hdr hdr = 
      eth::sadp::packet::BuildInquiry(_Socket.GetInterface());

  std::cout << "+ hdr at" << hdr << "\n";
  if (!hdr) return false;

  const int size = eth::sadp::packet::GetSize(hdr);
  if (size != -1) {
    _Socket.Send((char *)hdr, size);
  }
  return size != -1;
}

eth::sadp::sadp_hdr* eth::sadp::packet::BuildInquiry(
  const eth::adapter::NetInterface   *_Interface
) {
  if (!_Interface) {
    return nullptr;
  }

  eth::sadp::inquiry_payload payload;

  eth::ip::ToBytes(
    (const uint8_t *)_Interface->GetIpv6Address().c_str(),
    (uint8_t *)payload.f_inet6_address
  );

  eth::sadp::sadp_hdr *_Hdr = eth::sadp::packet::BuildFrame(
    _Interface,
    eth::sadp::sadp_packet_type::Request,
    eth::sadp::sadp_query_type::Inquiry,
    (const char *)&payload,
    16
  );

  return _Hdr;
}

eth::sadp::sadp_hdr *eth::sadp::packet::BuildFrame(
  const eth::adapter::NetInterface   *_Interface,
  const eth::sadp::sadp_packet_type   _PacketType,
  const eth::sadp::sadp_query_type    _QueryType,
  const char                         *_Payload,
  const size_t                        _Payload_Length,
  const uint16_t                      _ClientType
) noexcept {
  
  if (!_Interface) {
    return nullptr;
  }

  eth::sadp::psadp_hdr _Hdr = 
        (eth::sadp::psadp_hdr)malloc(DEFAULT_FRAME_SIZE);
  
  memset((void *)_Hdr, 0x00, DEFAULT_FRAME_SIZE);
  eth::sadp::psadp_frame _Frame = 
        (eth::sadp::psadp_frame)_Hdr->payload;

  _Hdr->h_proto = 0x3380;

  _Frame->f_packet_type = (uint8_t)_PacketType;
  _Frame->f_client_type = _ClientType;
  _Frame->f_counter = htonl(eth::GetCounter().GetAndIncrement());
  _Frame->f_type = (uint8_t)_QueryType;
  _Frame->f_prefix = 0x21U;
  _Frame->f_marker = 0x0406U;
  _Frame->f_parameters = 0x00;
  
   eth::mac::ToBytes(
    (const uint8_t *)_Interface->GetMacAddress().c_str(), 
    _Frame->f_src_mac
  );

  eth::mac::ToBytes(
    (const uint8_t *)"FF:FF:FF:FF:FF:FF",
    _Frame->f_dest_mac
  );

  eth::ip::ToBytes(
    _Interface->GetIpv4Address().c_str(), 
    &_Frame->f_src_ip
  );

  memcpy(
    (void *)_Frame->payload,
    (const void *)_Payload,
    _Payload_Length
  );

  eth::mac::ToBytes(
    (const uint8_t *)"FF:FF:FF:FF:FF:FF",
    (uint8_t *)_Hdr->h_dest
  );

  memcpy(
    (void *)_Hdr->h_src,
    (const void *)_Frame->f_src_mac,
    6 // mac address size
  );

  _Frame->f_checksum = htons((uint16_t)eth::sadp::Checksum(
    (unsigned short *)_Frame,
    ((unsigned int)_Frame->f_client_type >> 8) & 0xFF
  ));

  return _Hdr;
}

//--------------------------------------[Daemon]--------------------------------------

eth::sadp::Daemon::Daemon(eth::IISocket &_Socket) 
  : socket{_Socket}, running{false} {}

void eth::sadp::Daemon::Stop() 
{
  this->running = false;
}

const bool eth::sadp::Daemon::IsRunning() const
{
  return running;
}

void eth::sadp::Daemon::Start() 
{
  if (this->IsRunning()) {
    return;
  }

  this->running = true;
  // this->worker = std::thread([=]() {
  //    this->Run();
  // });
  // this->worker.join();
}

void eth::sadp::Daemon::Run() noexcept 
{
  // TEMPORARY: will be changed
  eth::sadp::psadp_hdr hdr;
  eth::sadp::psadp_frame frame;

  while (this->IsRunning()) {
    try {
      const int count = this->socket.Receive();
      if (count != -1) {
        hdr = (const eth::sadp::psadp_hdr)socket.GetBuffer();
        // check against the sadp protocol identifier
        if (ntohs(hdr->h_proto) == 0x8033) {
          std::cout << "+ SADP-Packet: " << (int)listenerList.size() << "\n";
          frame = (const eth::sadp::psadp_frame)hdr->payload;
          eth::event::PacketEvent pe(hdr, frame, &this->socket);

          for (size_t i = 0; i < listenerList.size(); i++) {
            listenerList.at(i)->onPacketReceived(pe);
          }
        }
      } 
    } 
    catch (...) {
      perror("Unexpected error");
    }
  }
}

const bool eth::sadp::Daemon::AddListener(
  const eth::event::PacketListener   *_Listener)
{
  if (_Listener) {
    this->listenerList.push_back(_Listener);
  }
  return _Listener != nullptr;
}

const bool eth::sadp::Daemon::RemoveListener(
  const eth::event::PacketListener   &_Listener)
{
  return false;//TODO
}

//--------------------------------------[sadp]--------------------------------------
