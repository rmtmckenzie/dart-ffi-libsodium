import 'dart:typed_data';

import 'dart:ffi';
import 'package:dart_sodium/src/ffi_helper.dart';

import 'src/bindings/auth.dart' as bindings;

/// Authenticates / Signs messages
class Authenticator {
  /// Produces random keys for an Authenticator
  static keyGen() {
    Pointer<Uint8> key;
    try {
      key = allocate(count: bindings.keyBytes);
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

  /// Authenticates / signs a message
  Uint8List authenticate(Uint8List msg) {
    Pointer<Uint8> out;
    Pointer<Uint8> msgPointer;
    try {
      out = allocate(count: bindings.authBytes);
      msgPointer = BufferToCString(msg);
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

  /// verifies a message and its tag
  bool verify(Uint8List msg, Uint8List tag) {
    Pointer<Uint8> tagPointer;
    Pointer<Uint8> msgPointer;
    try {
      tagPointer = BufferToCString(tag);
      msgPointer = BufferToCString(msg);
      final result = bindings.verify(tagPointer, msgPointer, msg.length, _key);
      return result == 0;
    } finally {
      tagPointer.free();
      msgPointer.free();
    }
  }

  /// Closes the Authenticator. Call this to avoid memory leaks.
  void close() {
    _key.free();
  }
}
