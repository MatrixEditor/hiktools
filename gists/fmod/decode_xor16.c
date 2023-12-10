typedef char byte;

void __cdecl DecodeXOR16(const byte *buffer, byte *dest, const int length)
{
  int index;
  byte key_byte;
  unsigned int *keyRef;
  unsigned int *pKey;
  unsigned int *key[4];

  // key reference here
  keyRef = &DAT_00404000;
  pKey = key;
  for (index = 4; index != 0; index--) {
    *pKey = *keyRef;
    keyRef++;
    pKey++;
  }
  if (length > 0) {
    do {
      key_byte = (byte)((int)key + (index + (index >> 4) & 0xFU));
      *(dest + index) = key_byte ^ *(buffer + index);
      index++;
    } while (index != length);
  }
  return;
}