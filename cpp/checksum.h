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
#if !defined(__SADP_CHECKSUM_H__)
#define __SADP_CHECKSUM_H__

namespace eth {

namespace sadp {

/**
 * @brief The code for a SADPClient.
 * 
 * While inspecting the network traffic between an hikvision ip-camera and the 
 * SADPTool, there was this code value when the SADPTool had send a message.
 */
#define CSADP_CLIENT_TYPE 0x4201

/**
 * @brief The code for a SADPServer.
 * 
 * Assuming the code defined above defines clients as the sender, this code 
 * indicated that a server built the received packet.
 */
#define CSADP_SERVER_TYPE 0xf601
  
/**
 * @brief  A small checksum generator for SADP Packets (Disassebled with Ghidra).
 * 
 * Note that the type value is always 0x42 (on the client side). To verify that, 
 * the x32dbg-Debugger was used.
 * 
 * @b Important: The input pointer should reference an array of little endian 
 * encoded bytes. For example, in wireshark you will see 0x2101 which has to be 
 * converted to 0x0221 (swap bytes).
 * 
 * @param header an unsinged short pointer to the start of the header of the 
 *               packet
 * @param type as defined above, the sender type
 * @return an unsigned integer value which contains the actual checksum within 
 *         the first two bytes.
 */
unsigned int Checksum(unsigned short *header, unsigned int type);

} // namespace sadp


} // namespace eth


#endif // __SADP_CHECKSUM_H__

