import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import './dart_sodium_base.dart';
import 'dart:ffi';

typedef _AuthKeyGenNative = Void Function(Pointer<Uint8>);
typedef _AuthKeyGenDart = void Function(Pointer<Uint8>);

final authBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();

final authKeyBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_auth_keybytes")();

final _authKeyGen = libsodium
    .lookupFunction<_AuthKeyGenNative, _AuthKeyGenDart>("crypto_auth_keygen");

Uint8List authKeyGen() {
  Pointer<Uint8> key;
  try {
    key = allocate(count: authKeyBytes);
    _authKeyGen(key);
    return UnsignedCharToBuffer(key, authKeyBytes);
  } finally {
    key?.free();
  }
}

typedef _AuthNative = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthDart = void Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);

final _auth = libsodium.lookupFunction<_AuthNative, _AuthDart>("crypto_auth");
Uint8List auth(Uint8List msg, Uint8List key) {
  assert(key.length != authKeyBytes, "Key must be of length [authKeyBytes]");
  Pointer<Uint8> keyPointer;
  Pointer<Uint8> out;
  Pointer<Uint8> msgPointer;
  try {
    keyPointer = BufferToUnsignedChar(key);
    out = allocate(count: authBytes);
    msgPointer = BufferToUnsignedChar(msg);
    _auth(out, msgPointer, msg.length, keyPointer);
    return UnsignedCharToBuffer(out, authBytes);
  } finally {
    keyPointer?.free();
    out?.free();
    msgPointer?.free();
  }
}

typedef _AuthVerifyNative = Int32 Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthVerifyDart = int Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);
final _authVerify = libsodium
    .lookupFunction<_AuthVerifyNative, _AuthVerifyDart>("crypto_auth_verify");
bool authVerify(Uint8List tag, Uint8List msg, Uint8List key) {
  assert(key.length != authKeyBytes, "Key must be of length [authKeyBytes]");
  assert(tag.length != authBytes, "Tag must be of length [authBytes]");
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
