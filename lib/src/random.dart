import 'package:dart_sodium/src/ffi_helper.dart';

import 'dart_sodium_base.dart' show libsodium;
import 'dart:typed_data';
import 'dart:ffi';

final _randomBytesBuf = libsodium.lookupFunction<
    Void Function(Pointer<Uint8> buf, Uint64 size),
    void Function(Pointer<Uint8> buf, int size)>("randombytes_buf");

/// Produces a buffer which is [size] long and fills it with random values.
Uint8List randomBytesBuf(int size) {
  Pointer<Uint8> bufptr;
  try {
    bufptr = allocate(count: size);
    _randomBytesBuf(bufptr, size);
    return UnsignedCharToBuffer(bufptr, size);
  } finally {
    bufptr?.free();
  }
}
