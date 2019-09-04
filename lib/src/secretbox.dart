import 'dart:typed_data';
import 'dart:ffi';
import 'ffi_helper.dart';

import 'bindings/secretbox.dart' as bindings;

/// Encrypts messages with the given key
class SecretBox {
  /// Generates a random key for [SecretBox]
  static Uint8List keyGen() {
    final Pointer<Uint8> key = allocate(count: bindings.keyBytes);
    try {
      bindings.keyGen(key);
      return CStringToBuffer(key, bindings.keyBytes);
    } finally {
      key.free();
    }
  }

  /// Required length of [nonce]
  static final nonceBytes = bindings.nonceBytes;

  /// Required length of [key]
  static final keyBytes = bindings.keyBytes;

  final Pointer<Uint8> _key;
  SecretBox(Uint8List key) : _key = BufferToCString(key) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw ArgumentError("Key hasn't expected length");
    }
  }

  /// Encrypts a message using the provided nonce.
  /// This nonce can be safely generated randomly (with a cryptographic
  /// random number generator like [random.buffer]) or be obtained by an atomic counter.
  Uint8List easy(Uint8List msg, Uint8List nonce) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    final cypherTextLen = bindings.macBytes + msg.length;
    final cypherText = allocate<Uint8>(count: cypherTextLen);
    final msgPtr = BufferToCString(msg);
    final noncePtr = BufferToCString(nonce);
    try {
      final secretBoxResult =
          bindings.easy(cypherText, msgPtr, msg.length, noncePtr, _key);
      if (secretBoxResult == -1) {
        throw Exception("Encrypting failed");
      }
      return CStringToBuffer(cypherText, cypherTextLen);
    } finally {
      cypherText.free();
      msgPtr.free();
      noncePtr.free();
    }
  }

  /// Decrypts a ciphertext generated by [easy] given the used [nonce]
  Uint8List openEasy(Uint8List cypherText, Uint8List nonce) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    final msgLen = cypherText.length - bindings.macBytes;
    final msgPtr = allocate<Uint8>(count: msgLen);
    final cPtr = BufferToCString(cypherText);
    final noncePtr = BufferToCString(nonce);
    try {
      final result =
          bindings.openEasy(msgPtr, cPtr, cypherText.length, noncePtr, _key);
      if (result == -1) {
        throw Exception("Decrypting failed");
      }
      return CStringToBuffer(msgPtr, msgLen);
    } finally {
      cPtr.free();
      noncePtr.free();
      msgPtr.free();
    }
  }

  /// Closes the SecretBox
  void close() {
    _key.free();
  }
}
