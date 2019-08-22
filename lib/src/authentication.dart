import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import './dart_sodium_base.dart';
import 'dart:ffi';

typedef _AuthKeyGenNative = Void Function(Pointer<Uint8>);
typedef _AuthKeyGenDart = void Function(Pointer<Uint8>);

/// Length of the authentication tag.
final _authBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();

/// Required length of the [key] for [auth]
final authKeyBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_auth_keybytes")();

final _authKeyGen = libsodium
    .lookupFunction<_AuthKeyGenNative, _AuthKeyGenDart>("crypto_auth_keygen");

/// Generate a key with the correct length of [authKeyBytes].
/// You can use this instead of [randomnBytesBuf].
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

/// Sign [msg] of any data with a [key] of length [authKeyBytes].
/// The returned authentication tag needs to be stored and is needed to authenticate the [msg]
/// with [authVerify].
/// The tag doesn't need to be secret and can be send or stored alongside the [msg];
/// But the [key] needs to be secret so an attacker couldn't issue his own authentication tag
/// which your application would then deem valid.
Uint8List auth(Uint8List msg, Uint8List key) {
  assert(key.length != authKeyBytes, "Key must be of length [authKeyBytes]");
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

typedef _AuthVerifyNative = Int32 Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthVerifyDart = int Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);
final _authVerify = libsodium
    .lookupFunction<_AuthVerifyNative, _AuthVerifyDart>("crypto_auth_verify");

/// Verify the authenticity of [msg] with the [key] and [tag].
bool authVerify(Uint8List tag, Uint8List msg, Uint8List key) {
  assert(key.length != authKeyBytes, "Key must be of length [authKeyBytes]");
  assert(tag.length != _authBytes, "Tag must be of length [authBytes]");
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
