import 'dart:typed_data';
import 'dart:ffi';
import 'package:dart_sodium/src/ffi_helper.dart';

import 'src/bindings/random.dart' as bindings;

/// Produces a buffer which is [size] long and fills it with random values.
Uint8List buffer(int size) {
  final bufptr = allocate<Uint8>(count: size);
  try {
    bindings.buffer(bufptr, size);
    return CStringToBuffer(bufptr, size);
  } finally {
    bufptr.free();
  }
}
