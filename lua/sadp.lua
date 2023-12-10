--[[
The MIT License (MIT)

Copyright (c) 2023 MatrixEditor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

do
  local sadp_eth_type = 0x8033
  local sadp_header_length = 0x26

  local sadp_proto = Proto("SADP", "Search Active Device Protocol")

  local packet_type = {
    [1] = "Response Packet",
    [2] = "Request Packet"
  }
  
  local query_type = {
    [0x02] = "DeviceOnlineRequest",
    [0x03] = "Inquiry",
    [0x04] = "InquiryResponse",
    [0x06] = "UpdateIP",
    [0x07] = "UpdateIPResponse",
    [0x0a] = "ResetPassword",
    [0x0b] = "ResetPasswordResponse",
    [0x0c] = "CMSInfo",
    [0x0d] = "CMSInfoResponse",
    [0x10] = "ModifyNetParam",
    [0x11] = "ModifyNetParamResponse"
  }

  local origin_type = {
    [0xF] = "Packet was sent by Device",
    [0x4] = "Packet was sent by SADP Tool",
  }

  local F_header_marker     = ProtoField.uint8("sadp.header.marker", "Marker", base.HEX)
  local F_header_type       = ProtoField.uint8("sadp.header.type", "Type", base.HEX, packet_type, 0xF)
  local F_header_origin     = ProtoField.uint16("sadp.header.origin", "Origin", base.HEX, origin_type, 0xF0)
  local F_header_counter    = ProtoField.uint32("sadp.header.counter", "Counter", base.DEC) 
  local F_header_marker2    = ProtoField.uint16("sadp.header.marker2", "Marker2", base.HEX)
  local F_header_checksum   = ProtoField.uint16("sadp.header.checksum", "Checksum", base.HEX)
  local F_header_qry_type   = ProtoField.uint8("sadp.header.qry.type", "Query Type", base.HEX, query_type, 0xF)
  local F_header_qry_params = ProtoField.uint8("sadp.header.qry.params", "Query Params", base.HEX)
  local F_header_cur_mac    = ProtoField.new("Current MAC","sadp.header.cur.mac", ftypes.ETHER)
  local F_header_dst_mac    = ProtoField.new("Destination MAC", "sadp.header.dst.mac", ftypes.ETHER)
  local F_header_cur_ip     = ProtoField.new("Current IP", "sadp.header.cur.ip", ftypes.IPv4)
  local F_header_dst_ip     = ProtoField.new("Destination IP", "sadp.header.dst.ip", ftypes.IPv4)
  local F_header_add_ip     = ProtoField.new("Subnet Mask", "sadp.header.subnet", ftypes.IPv4)
  
  local F_payload_data = ProtoField.new("Data", "sadp.payload.data", ftypes.BYTES)
  local F_payload_ipv6 = ProtoField.new("Current IPv6", "sadp.payload.ipv6", ftypes.IPv6)

  -- add the fields to the protocol
  sadp_proto.fields = {
    -- header
    F_header_marker, F_header_type, F_header_origin,
    F_header_counter, F_header_marker2, F_header_qry_type, F_header_qry_params,
    F_header_cur_mac, F_header_dst_mac, F_header_cur_ip, F_header_dst_ip,
    F_header_add_ip, F_header_checksum,

    -- payload
    F_payload_data, F_payload_ipv6
  }


  local function sadp_dissector(buffer, pinfo, tree)
    buf_len = buffer:len()
    if buf_len == 0 then return end

    pinfo.cols.protocol = sadp_proto.name

    local subtree = tree:add(sadp_proto, buffer(), "Search Active Device Protocol")
    local header = subtree:add(sadp_proto, buffer(0, sadp_header_length), "Header")

    local marker = buffer(0, 1):le_int()
    if marker == 0x21 then
      header:add_le(F_header_marker, buffer(0, 1)):append_text(" (default)")
    else
      header:add_le(F_header_marker, buffer(0, 1))
    end

    local _type = buffer(1, 1):le_int()
    if _type == nil then
      _type = 0x1
    end

    type_subtree = header:add(sadp_proto, buffer(1, 1), "Type: " .. packet_type[_type])
    type_subtree:add(F_header_type, buffer(1, 1))

    _origin = buffer(2, 2):le_int()
    
    if _origin == 0x4201 then 
      origin_subtree = header:add(sadp_proto, buffer(2, 2), "Origin: SADP Tool")
    else
      origin_subtree = header:add(sadp_proto, buffer(2, 2), "Origin: Device")
    end
    origin_subtree:add(F_header_origin, buffer(3, 1))

    header:add(F_header_counter, buffer(4, 4))
    marker = buffer(8, 2):le_int()
    if marker == 0x0406 then
      header:add_le(F_header_marker2, buffer(8, 2)):append_text(" (default)")
    else
      header:add_le(F_header_marker2, buffer(8, 2))
    end

    if _type == 1 then
      _ptype = buffer(10, 1):le_int() - 1
    end

    _type = buffer(10, 1):le_int()

    
    local query_subtree = header:add(sadp_proto, buffer(10, 2), "Query Type: " .. query_type[_ptype])
    query_subtree:add(F_header_qry_type, buffer(10, 1))
    query_subtree:add(F_header_qry_params, buffer(11, 1))

    header:add(F_header_checksum, buffer(12, 2))

    header:add(F_header_cur_mac, buffer(14, 6))
    header:add(F_header_cur_ip,  buffer(20, 4))
    header:add(F_header_dst_mac, buffer(24, 6))
    header:add(F_header_dst_ip,  buffer(30, 4))
    header:add(F_header_add_ip,  buffer(34, 4))

    local payload_tree = subtree:add(sadp_proto, buffer(sadp_header_length, buf_len - sadp_header_length), "Payload")

    if _type == 0x03 then
      payload_tree:add(F_payload_ipv6, buffer(sadp_header_length, sadp_header_length + 16))
    else
      payload_tree:add(F_payload_data, buffer(sadp_header_length, buf_len - sadp_header_length))
    end

  end

  -- declare the fields we need to read
  function sadp_proto.dissector(tvbuffer, pinfo, treeitem)
    return sadp_dissector(tvbuffer, pinfo, treeitem)
  end

  local eth_Type = DissectorTable.get("ethertype")
  eth_Type:add(0x8033, sadp_proto)
end


