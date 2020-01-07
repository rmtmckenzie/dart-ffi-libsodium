import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/helpers.dart' as bindings;

bool memoryCompare(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    throw ArgumentError('Both arguments must have the same length');
  }

  final aPtr = Uint8Array.fromTypedList(a);
  final bPtr = Uint8Array.fromTypedList(b);

  final result = bindings.memoryCompare(aPtr.rawPtr, bPtr.rawPtr, a.length);
  aPtr.free();
  bPtr.free();
  return result == 0;
}
