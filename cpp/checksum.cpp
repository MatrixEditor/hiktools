#include "checksum.h"

unsigned int eth::sadp::Checksum(unsigned short *header, unsigned int prefix)
{
  unsigned int checksum = 0;

  int var1 = 0;
  int var2 = 0;
  int index = 0;

  unsigned short *pHeader = header;
  
  if (3 < (prefix & 0xFFFFFFFE)) {
    // When a SADPTool instance tries build a packet, 0x42 is provided as
    // the prefix number.
    index = (prefix - 4 >> 2) + 1;
    do {
      prefix -= 4;
      var1 += (unsigned int)pHeader[0];
      var2 += (unsigned int)pHeader[1];

      pHeader = pHeader + 2;
      index -= 1; 
    } while (index != 0);
  }

  if (1 < prefix) {
    // On simple inquiry packets, this additional sum computing
    // does not change anything.
    checksum = (unsigned int)*pHeader;
    pHeader++;
    prefix -= 2;
  }

  checksum += var1 + var2;
  if (prefix != 0) {
    checksum += *(unsigned char *)(pHeader);
  }

  checksum = (checksum >> 16) + (checksum & 0xFFFF);
  return ~((checksum >> 16) + checksum);
}