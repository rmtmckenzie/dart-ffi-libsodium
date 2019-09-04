import 'dart:typed_data';

import 'dart:ffi';
import 'ffi_helper.dart';

import 'bindings/auth.dart' as bindings;

/// Message authentication
class Authenticator {
  /// Generates a random key for [Authenticator]
  static keyGen() {
    final key = allocate<Uint8>(count: bindings.keyBytes);
    try {
      bindings.keyGen(key);
      return CStringToBuffer(key, bindings.keyBytes);
    } finally {
      key.free();
    }
  }

  final Pointer<Uint8> _key;
  Authenticator(Uint8List key) : _key = BufferToCString(key) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw ArgumentError("Key hasn't expected length");
    }
  }

  /// Generates an authentication tag for [msg]
  Uint8List authenticate(Uint8List msg) {
    final out = allocate<Uint8>(count: bindings.authBytes);
    final msgPointer = BufferToCString(msg);
    try {
      final authResult = bindings.auth(out, msgPointer, msg.length, _key);
      if (authResult != 0) {
        throw Exception("Authentication failed");
      }
      return CStringToBuffer(out, bindings.authBytes);
    } finally {
      out.free();
      msgPointer.free();
    }
  }

  /// Verifies a message and its tag produced by [authenticate]
  bool verify(Uint8List msg, Uint8List tag) {
    final tagPointer = BufferToCString(tag);
    final msgPointer = BufferToCString(msg);
    try {
      final result = bindings.verify(tagPointer, msgPointer, msg.length, _key);
      return result == 0;
    } finally {
      tagPointer.free();
      msgPointer.free();
    }
  }

  /// Closes the Authenticator.
  void close() {
    _key.free();
  }
}
