import 'dart:typed_data';
import 'dart:ffi';

import 'package:dart_sodium/src/ffi_helper.dart';
import 'src/bindings/helpers.dart' as bindings;

/// Compares two buffers in constant-time.
/// You should use this instead of simple comparison using the [==] operator
/// when you are comparing sensitive information like authentication tags
/// to avoid side-channel attacks like timing-attacks.
///
/// The [buffer] should be a value provided by the user while [compareTo]
/// is the value the [buffer] gets compared to. This is important because the
/// comparison depends on the length of [buffer] to avoid leaking information
/// about the length of [compareTo].
bool memoryCompare(Uint8List buffer, Uint8List compareTo) {
  final firstPtr = BufferToCString(buffer);
  final secondPtr = BufferToCString(compareTo);
  try {
    final result = bindings.memoryCompare(firstPtr, secondPtr, buffer.length);
    return result == 0;
  } finally {
    firstPtr.free();
    secondPtr.free();
  }
}
