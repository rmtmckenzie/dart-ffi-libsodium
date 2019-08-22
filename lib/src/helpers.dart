import 'dart:typed_data';

import './dart_sodium_base.dart';
import './ffi_helper.dart';
import 'dart:ffi';

typedef _SodiumMemcmpNative = Int16 Function(
    Pointer<Uint8> b1, Pointer<Uint8> b2, Uint64 len);
typedef _SodiumMemcmpDart = int Function(
    Pointer<Uint8> b1, Pointer<Uint8> b2, int len);
final _memcmp = libsodium
    .lookupFunction<_SodiumMemcmpNative, _SodiumMemcmpDart>("sodium_memcmp");

/// Constant time comparison of two buffers.
/// You should use this instead of simple comparison using the [==] operator
/// when you are comparing sensitive information like authentication tags
/// to avoid side-channel attacks like timing-attacks.
///
/// The [buffer] should be a value provided by the user while [compareTo]
/// is the value the [buffer] gets compared to. This is important because the
/// comparison depends on the length of [buffer] to avoid leaking information
/// about the length of [compareTo].
bool memCmp(Uint8List buffer, Uint8List compareTo) {
  Pointer<Uint8> firstPtr, secondPtr;
  try {
    firstPtr = BufferToUnsignedChar(buffer);
    secondPtr = BufferToUnsignedChar(compareTo);
    final result = _memcmp(firstPtr, secondPtr, buffer.length);
    return result == 0;
  } finally {
    firstPtr?.free();
    secondPtr?.free();
  }
}
