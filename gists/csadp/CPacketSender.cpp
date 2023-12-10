#include <string.h>

#define __stack_chk_fail(x) 

typedef int __stack_chk_guard;

class CPacketSender;

class CAdapterInfo {
  public:
    static void *Instance();
    static void GetCurAdapterMAC(CAdapterInfo *pInfo, unsigned short index, char *__dst);
    static void GetCurAdapterIP(CAdapterInfo *pInfo, unsigned short index, char *__dst);
};

void FormatStrToMAC(char *__src, unsigned char *__dst);
void FormatStrToIP(char *__src, unsigned long *__dst);
unsigned long SwapULong(unsigned long value);
unsigned int SwapUInt(unsigned int value);
unsigned int CheckSum(CPacketSender *pSender, unsigned short *buffer, unsigned int param_2);

void BuildSADPPacket(char *buffer, char *dest_mac, char *ip_address, unsigned char param_4,
                     char *cur_adapter_ipv6, unsigned char packet_type, unsigned char param_6,
                     unsigned short membuffer, unsigned short mem_len, unsigned short adapter_index) 
{
  CAdapterInfo *pInfo;

  size_t __n;
  long local8;

  unsigned long checksum; 
  unsigned long cur_mac;
  unsigned long cur_ip;
  unsigned long ether_type;
  unsigned long header_start;
  unsigned long payload_start;
  unsigned short actual_size;
  unsigned int next_ip;

  char *buffer_start;
  unsigned short *buffer_footer;
  unsigned long *header_buffer;
  unsigned long *out_buffer;
  
  local8 = __stack_chk_guard();
  // NOTE: At first, there are some checks around the starting point of the 
  // buffer. Note, that the actual starting address is (buffer + 0x18).
  buffer_start = *(char **)(buffer + 0x10);
  if (buffer_start == (char *)0x00) {
    actual_size = 0;
  }
  else if (*(long *)(buffer + 0x18) == 0x0) {
    // The start of the packet buffer is 0x00 
    actual_size = 0;
  }
  else {
    *buffer_start = 0;
    
    // Make sure, the checksum field and starting point are filled up with 0's.
    *(unsigned short *)((long)buffer_start + 0xc) = 0x0;
    *(unsigned int *)(buffer_start + 0x1) = 0x0;

    // Clear the buffer of 512 bytes.
    memset((void *)(buffer + 0x18), 0x0, 0x200);

    // Retrive the current MAC and IP address:
    pInfo = (CAdapterInfo *)CAdapterInfo::Instance();
    CAdapterInfo::GetCurAdapterMAC(pInfo, adapter_index, (char *)&cur_mac);
    pInfo = (CAdapterInfo *)CAdapterInfo::Instance();
    CAdapterInfo::GetCurAdapterIP(pInfo, adapter_index, (char *)&cur_ip);

    if (mem_len < 0x1C) {
      actual_size = 0x50;
      __n = 0x1C;
    }
    else {
      actual_size = mem_len + 0x34;
      __n = (size_t)(int)(actual_size - 0x34);
    }


    header_start = *(long *)(buffer + 0x10);
    FormatStrToMAC(dest_mac, (unsigned char *)header_start);
    FormatStrToMAC((char *)&cur_mac, (unsigned char *)(header_start + 6));
    
    // Big endian encoding is used. According to IEEE, the ether type 8033
    // is registered to: (https://standards-oui.ieee.org/ethertype/eth.txt)
    //    VIA Systems 
    //    76  Treble Cove Road                                                                                     
    //    N. Billerica  MA  08162, US   
    ether_type = SwapULong(0xffff8033);
    *(short *)(header_start + 0xc) = (short) ether_type; 

    // This code fills up the header values up to byte 12:
    payload_start = *(long *)(buffer + 0x18);
    *((char *)payload_start) = 0x21;
    *((char *)payload_start + 1) = 0x02;
    *((char *)payload_start + 2) = 0x01;
    *((char *)payload_start + 3) = 0x42;
    *((unsigned int *)payload_start + 4) = SwapUInt((unsigned int)(cur_adapter_ipv6));
    *((char *)payload_start + 8) = 0x06;
    *((char *)payload_start + 9) = 0x04;
    *((unsigned char *)payload_start + 10) = packet_type;
    *((char *)payload_start + 11) = (char)(param_6);
    *((char *)payload_start + 12) = 0x00;

    // Next, the current mac and destination mac address are set together with the
    // local and target ip address.
    FormatStrToMAC((char *)&cur_mac, (unsigned char *)(payload_start + 14));
    FormatStrToIP((char *)&cur_ip, (unsigned long *)(*(long *)(payload_start) + 20));
    FormatStrToMAC(dest_mac, (unsigned char *)(payload_start + 24));

    next_ip = 0x00;
    FormatStrToIP(ip_address, (unsigned long *)&next_ip);
    *(unsigned int *)(*(long *)(payload_start) + 30) = next_ip;

    FormatStrToIP((char *)(unsigned long)param_4, (unsigned long *)&next_ip);
    *(unsigned int *)(*(long *)(payload_start) + 34) = next_ip;

    // Copy given data into buffer.
    memcpy(
      (void *)(*(long *)(payload_start) + 38),
      (const void *)(unsigned long) membuffer,
      (unsigned long) mem_len
    );

    buffer_footer = (unsigned short *)(payload_start);
    checksum = CheckSum((CPacketSender *)buffer, buffer_footer, (unsigned int) *(char *)((long) buffer_footer + 3));
    buffer_footer[6] = (unsigned short) SwapULong(checksum);
  }


  // At the end there is a check if a stack overflow was detected.
  if (local8 == __stack_chk_guard()) {
    return;
  }
  __stack_chk_fail(actual_size)
}