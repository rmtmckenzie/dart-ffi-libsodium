import 'dart:typed_data';

import 'dart:ffi';
import 'package:dart_sodium/src/ffi_helper.dart';

import 'src/bindings/auth.dart' as bindings;

class Authenticator {
  static keyGen() {
    Pointer<Uint8> key;
    try {
      key = allocate(count: bindings.keyBytes);
      bindings.keyGen(key);
      return CString.toUint8List(key, bindings.keyBytes);
    } finally {
      key.free();
    }
  }

  CString _key;
  Authenticator(Uint8List key) : _key = CString.fromUint8List(key) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw ArgumentError("Key hasn't expected length");
    }
  }

  Uint8List authenticate(Uint8List msg) {
    Pointer<Uint8> out;
    Pointer<Uint8> msgPointer;
    try {
      out = allocate(count: bindings.authBytes);
      msgPointer = CString.fromUint8List(msg);
      final authResult = bindings.auth(out, msgPointer, msg.length, _key);
      if (authResult != 0) {
        throw Exception("Authentication failed");
      }
      return CString.toUint8List(out, bindings.authBytes);
    } finally {
      out.free();
      msgPointer.free();
    }
  }

  bool verify(Uint8List tag, Uint8List msg) {
    Pointer<Uint8> tagPointer;
    Pointer<Uint8> msgPointer;
    try {
      tagPointer = CString.fromUint8List(tag);
      msgPointer = CString.fromUint8List(msg);
      final result = bindings.verify(tagPointer, msgPointer, msg.length, _key);
      return result == 0;
    } finally {
      tagPointer.free();
      msgPointer.free();
    }
  }

  void close() {
    _key.free();
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
    keyPointer = CString.fromUint8List(key);
    out = allocate(count: bindings.authBytes);
    msgPointer = CString.fromUint8List(msg);
    bindings.auth(out, msgPointer, msg.length, keyPointer);
    return CString.toUint8List(out, authBytes);
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
