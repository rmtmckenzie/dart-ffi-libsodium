import 'dart:typed_data';
import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/random.dart' as bindings;
import 'helper.dart';

/// Generates a sequence of [size] random numbers
UnmodifiableUint8ListView buffer(int size) {
  final bufPtr = Uint8Array.allocate(count: size);
  bindings.buffer(bufPtr.rawPtr.cast(), size);
  bufPtr.view.fillZero();
  bufPtr.free();
  return UnmodifiableUint8ListView(Uint8List.fromList(bufPtr.view));
}
