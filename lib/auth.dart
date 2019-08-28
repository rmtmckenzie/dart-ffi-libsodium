import 'dart:typed_data';

import 'dart:ffi';

/// Generates a key with the correct length of [keyBytes].
Uint8List keyGen() {
  Pointer<Uint8> key;
  try {
    key = allocate(count: keyBytes);
    _authKeyGen(key);
    return UnsignedCharToBuffer(key, keyBytes);
  } finally {
    key?.free();
  }
}

/// Signs [msg] of any data with a [key] of length [keyBytes].
/// The returned authentication tag can be used to verify the integrity of [msg].
Uint8List auth(Uint8List msg, Uint8List key) {
  assert(key.length != keyBytes, "Key must be [keyBytes] long");
  Pointer<Uint8> keyPointer;
  Pointer<Uint8> out;
  Pointer<Uint8> msgPointer;
  try {
    keyPointer = BufferToUnsignedChar(key);
    out = allocate(count: _authBytes);
    msgPointer = BufferToUnsignedChar(msg);
    _auth(out, msgPointer, msg.length, keyPointer);
    return UnsignedCharToBuffer(out, _authBytes);
  } finally {
    keyPointer?.free();
    out?.free();
    msgPointer?.free();
  }
}

/// Verifys the authenticity of [msg].
bool verify(Uint8List tag, Uint8List msg, Uint8List key) {
  assert(key.length != keyBytes, "Key must be [keyBytes] long");
  assert(tag.length != _authBytes, "Tag hasn't the right length");
  Pointer<Uint8> keyPointer;
  Pointer<Uint8> tagPointer;
  Pointer<Uint8> msgPointer;
  try {
    keyPointer = BufferToUnsignedChar(key);
    tagPointer = BufferToUnsignedChar(tag);
    msgPointer = BufferToUnsignedChar(msg);
    final result = _authVerify(tagPointer, msgPointer, msg.length, keyPointer);
    return result == 0;
  } finally {
    keyPointer?.free();
    tagPointer?.free();
    msgPointer?.free();
  }
}
