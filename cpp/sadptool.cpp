#include "sadplib.h"

#include <string>
#include <iostream>
#include <iomanip>

class MyHandler : public eth::event::PacketListener {
  public:
    virtual void onPacketReceived(const eth::event::PacketEvent &_Event) const override
    {
      //TODO maybe add source
      std::cout << "+ Received a packet ("
                <<  eth::sadp::QueryTypeToString(
                    _Event.GetSADPFrame()->f_type,
                    (eth::sadp::sadp_packet_type)_Event.GetSADPFrame()->f_packet_type)
                <<")\n";
    }
};

int main(int argc, char const *argv[]) 
{
  eth::GetCounter().Set(0x1c80);

  MyHandler handler;

  std::cout << "i Lookup...\n";
  const eth::adapter::NetInterfaceList *list = eth::adapter::GetNetInterfaces();
  std::cout << "+ List at " << list << " (" << list->size()<< ")\n";
  
  const size_t count = list->size();
  for (size_t i = 0; i < count; i++)
  {
    std::cout.flush();
    const eth::adapter::NetInterface &ni = list->at(i);

    if (ni.GetInterfaceIndex() == 3) {
      std::cout << "+ Found NetInterface...\n";
      eth::IISocket sock;

      if (sock.Create(&ni, 0x3380)) {
        std::cout << "+ Created socket with proto 0x8033\n";
      }
      
      sock.Bind();

      eth::sadp::Daemon daemon(sock);
      daemon.AddListener(&handler);
      daemon.Start();

      eth::sadp::packet::SendInquiry(sock);

      daemon.Run();
      daemon.Stop();
      break;
    }
  }
  
  return 0;
}
