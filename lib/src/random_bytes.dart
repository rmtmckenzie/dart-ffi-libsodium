import 'dart:typed_data';
import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/random.dart' as bindings;
import 'internal_helpers.dart';

/// Generates a sequence of [size] random numbers
UnmodifiableUint8ListView buffer(int size) {
  final bufPtr = Uint8Array.allocate(count: size);
  bindings.buffer(bufPtr.rawPtr.cast(), size);
  bufPtr.view.fillZero();
  bufPtr.free();
  return UnmodifiableUint8ListView(Uint8List.fromList(bufPtr.view));
}

/// Generates a sequence of [size] pseudo-random numbers.
/// [seed] must be [seedBytes] long. The same [seed] produces the same
/// sequence of pseudo-random numbers.
UnmodifiableUint8ListView bufferDeterministic(int size, Uint8List seed) {
  final bufPtr = Uint8Array.allocate(count: size);
  final seedPtr = Uint8Array.fromTypedList(seed);

  bindings.bufferDeterministic(bufPtr.rawPtr.cast(), size, seedPtr.rawPtr);
  bufPtr.free();
  seedPtr.free();
  return UnmodifiableUint8ListView(Uint8List.fromList(bufPtr.view));
}
