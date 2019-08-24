import 'dart:ffi';
import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import './src/dart_sodium_base.dart';

final _keyGen = libsodium.lookupFunction<
    Void Function(Pointer<Uint8> key),
    void Function(
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_keygen");
final _keyBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_keybytes")();
final _headerBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_secretstream_xchacha20poly1305_headerbytes");

class SecretStream {
  static Uint8List keyGen() {
    Pointer<Uint8> key;
    try {
      key = allocate(count: _keyBytes);
      _keyGen(key);
      return UnsignedCharToBuffer(key, _keyBytes);
    } finally {
      key?.free();
    }
  }
}
