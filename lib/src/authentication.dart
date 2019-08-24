import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import './dart_sodium_base.dart';
import 'dart:ffi';

typedef _AuthKeyGenNative = Void Function(Pointer<Uint8>);
typedef _AuthKeyGenDart = void Function(Pointer<Uint8>);

final _authKeyGen = libsodium
    .lookupFunction<_AuthKeyGenNative, _AuthKeyGenDart>("crypto_auth_keygen");

/// Length of the authentication tag.
final _authBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();

typedef _AuthNative = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthDart = void Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);

final _auth = libsodium.lookupFunction<_AuthNative, _AuthDart>("crypto_auth");

typedef _AuthVerifyNative = Int32 Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthVerifyDart = int Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);
final _authVerify = libsodium
    .lookupFunction<_AuthVerifyNative, _AuthVerifyDart>("crypto_auth_verify");

abstract class Auth {
  /// Required length of the [key]
  static final keyBytes =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_auth_keybytes")();

  /// Generates a key with the correct length of [keyBytes].
  static Uint8List keyGen() {
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
  static Uint8List auth(Uint8List msg, Uint8List key) {
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
  static bool verify(Uint8List tag, Uint8List msg, Uint8List key) {
    assert(key.length != keyBytes, "Key must be [keyBytes] long");
    assert(tag.length != _authBytes, "Tag hasn't the right length");
    Pointer<Uint8> keyPointer;
    Pointer<Uint8> tagPointer;
    Pointer<Uint8> msgPointer;
    try {
      keyPointer = BufferToUnsignedChar(key);
      tagPointer = BufferToUnsignedChar(tag);
      msgPointer = BufferToUnsignedChar(msg);
      final result =
          _authVerify(tagPointer, msgPointer, msg.length, keyPointer);
      return result == 0;
    } finally {
      keyPointer?.free();
      tagPointer?.free();
      msgPointer?.free();
    }
  }
}
