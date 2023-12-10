# MIT License
#
# Copyright (c) 2023 MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Small module that contains message declarations for UDP communication.
"""

__all__ = [
    "SADPMessage",
    "fromdict",
    "BasicDictObject",
    "DiscoveryPacket",
    "SafeCode",
    "DeviceSafeCodePacket",
    "unmarshal",
    "ActionResponse",
]

import xml.etree.ElementTree as xmltree
import ctypes
import base64

from typing import Iterator, overload

__types__ = {}
"""A dict object storing all defined message types.
"""


def message_type(name: str):
    """Registers a new message type.

    :param name: the name of the type to register
    :type name: str
    """

    def wrapper(clazz):
        if name not in __types__:
            __types__[name] = clazz
        return clazz

    return wrapper


class SADPMessage:
    """A simple exchange class.

    For exchanging data between the client and the device this object wrapper
    is used. It stores the message string which is sent over broadcast to the
    device and the response as bytes.

    :param response: A response buffer storing the received bytes.
    :type response: bytes
    """

    def __init__(
        self, message: str = None, response=None, sender: tuple = None
    ) -> None:
        self._message = message
        self._response = response
        self._sender = (None, 0) if not sender else sender

    def toxml(self) -> xmltree.Element:
        """Transforms the received bytes into an XML element."""
        if self._response is not None:
            return xmltree.fromstring(self._response)
        else:
            raise ValueError("Response value is null")

    def set_response(self, response: bytes):
        """The message's response setter.

        :param response: the raw response onbject
        :type response: bytes
        """
        if response is not None:
            self._response = response

    @property
    def address(self) -> str:
        """The sender ip address. (DO NOT USE)"""
        return self._sender[0]

    @property
    def message(self) -> str:
        """The initial message formatted as an XML string."""
        return self._message

    @property
    def sender(self) -> tuple:
        """The sender ip address and port. (DO NOT USE)"""
        return self._sender

    def __bytes__(self) -> bytes:
        return self.message.encode("utf-8")

    def __repr__(self) -> str:
        return self.message

    def __str__(self) -> str:
        return self.message


def fromdict(value: dict) -> SADPMessage:
    """Converts a dict object into an SADPMessage object.

    :param value: The input dict containing the XML nodes.
    :type value: dict

    :returns: An message object containing all nodes of the given
                dict object converted into an XML string.
    :rtype: SADPMessage
    """
    root = xmltree.Element("Probe")
    for key in value:
        elem = xmltree.Element(key)
        elem.text = value[key]
        root.append(elem)
    return SADPMessage(
        message=xmltree.tostring(root, xml_declaration=True).decode("utf-8")
    )


def pack(buffer: bytes, fmt: type, index=0) -> int:
    """Puts the bytes in the given buffer into one integer.

    :param buffer: the input buffer
    :type buffer: bytes
    :param fmt: the integer type
    :type fmt: type
    :param index: the current buffer position, defaults to 0
    :type index: int, optional
    :return: the packed integer variable
    :rtype: int
    """
    if fmt == ctypes.c_uint32:
        return (
            pack(buffer, ctypes.c_uint16, index)
            | pack(buffer, ctypes.c_uint16, index + 2) << 16
        )
    if fmt == ctypes.c_uint8:
        return fmt(buffer[index])
    if fmt == ctypes.c_uint16:
        return (
            pack(buffer, ctypes.c_uint8, index)
            | pack(buffer, ctypes.c_uint8, index + 1) << 8
        )
    raise TypeError(f'Invalid type "{str(fmt)}" - not implemented!')


class BasicDictObject:
    """The base class for response objects.

    A small wrapper class implementing basic dict behaviour.

    Example usage:
    >>> base = BaseDictObject()
    >>> base['hello'] = "World"
    >>> print(str(base))
    <BaseDictObject><hello>World</hello></BaseDictObject>
    >>> print(repr(base))
    <BaseDictObject object>
    """

    def __init__(self, root: xmltree.Element = None, exclude: list = None) -> None:
        self._capabilities = {}
        if root is not None:
            for capability in root:
                if not exclude or capability not in exclude:
                    self[capability.tag] = capability.text

    def __setitem__(self, key, value):
        self._capabilities[key] = value

    def __getitem__(self, key):
        return self._capabilities[key]

    def __contains__(self, item):
        return str(item) in self._capabilities

    def __iter__(self) -> Iterator[str]:
        return iter(self._capabilities)

    def __str__(self) -> str:
        text = [f"<{self.__class__.__name__}>"]
        for cap_name in self:
            text.append(f"\t<{cap_name}>{self[cap_name]}</{cap_name}>")
            text.append(f"</{self.__class__.__name__}>")
        return "\n".join(text)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} object>"


@message_type("inquiry")
class DiscoveryPacket(BasicDictObject):
    """A simple discovery packet response wrapper.

    Contains all information related to the inquiry response packet. Possible
    nodes are:

    `DeviceType`, `DeviceDescription`, `CommandPort`, `HttpPort`, `MAC`, `Ipv4Address`,
    `Ipv4SubnetMask`, `Ipv4Gateway`, `Ipv6Address`, `Ipv6Masklen`, `Ipv6Gateway`, `DHCP`,
    `AnalogChannelNum`, `DigitalChannelNum`, `DSPVersion`, `Activated` and
    `PasswordResetAbility`.
    """


class SafeCode:
    """The device's safe code wrapper class.

    A safe code is requested by the SADP Tool to export it and send it to the
    customer service. An unlock code should be returned which can reset the device.
    """

    SAFECODE_FLAG = "03000000"
    """Safe code header value"""

    @overload
    def __init__(self, code: bytes) -> None:
        ...

    def __init__(self, code: str) -> None:
        if not code:
            raise ValueError("Code argument has to be non null!")

        self._b64_encoded = code.encode("utf-8") if isinstance(code, str) else code
        self._b64_decoded = base64.decodebytes(self._b64_encoded)

        if self._b64_decoded[:4].hex() != self.SAFECODE_FLAG:
            raise ValueError(
                "Invalid SafeCode: expected %#x as flag" % self.SAFECODE_FLAG
            )

        self._code = str(self._b64_decoded[4:-4], "utf-8")
        self._cksum = pack(self._b64_decoded[:-4], ctypes.c_uint32)

    @property
    def checksum(self) -> ctypes.c_uint32:
        """The checksum stored in the safe code."""
        return self._cksum

    @property
    def code(self) -> str:
        """The full safe code as a string"""
        return self._code

    def __repr__(self) -> str:
        return self.code


@message_type("getcode")
class DeviceSafeCodePacket(BasicDictObject):
    """A response packet for the 'getcode' message.

    This class can contain the following nodes:

    `MAC`, `Uuid`, `Code`, `Types`
    """

    @property
    def code(self) -> str:
        """The base64 safecode string."""
        return self["Code"]

    def get_safecode(self) -> SafeCode:
        """Returns the converted safecode as a SafeCode object."""
        return SafeCode(self.code)


@message_type("reset")
class ActionResponse(BasicDictObject):
    """A 'reset' message response packet.

    The response packet just contains one field of interest named 'Result'. It
    applies to the following values: failure, success, denied
    """

    def __init__(self, root: xmltree.Element = None) -> None:
        super().__init__(root)

    @property
    def success(self) -> bool:
        """Returns whether the action invocation was successful."""
        return self["Result"] == "success"


def unmarshal(root: xmltree.Element):
    """Tries to de-serialize an XML-String.

    Possible object types are: DiscoveryPacket, DeviceSafeCodePacket, ActionResponse,
    and BasicDictObject for messages that are not implemented yet.

    :param root:  The XML root element (non null).
    :type root: xmltree.Element
    :return: A qualified object instance or None if the given argument was None or
             the input could not be converted.
    :rtype: ? extends BasicDictObject, None
    """
    if root is None:
        raise ValueError("Input argument is null")

    req_type = root.find("Types")
    if req_type is None:
        return None

    for type_name, cls in __types__.items():
        if type_name == req_type.text.lower():
            return cls(root=root)
    return BasicDictObject(root=root)
