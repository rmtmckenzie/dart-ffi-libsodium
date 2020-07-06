import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/random.dart' as bindings;
import 'internal_helpers.dart';

class RandomBytes {
  final bindings.RandomBytes _randomBytes;

  RandomBytes({bindings.RandomBytes randomBytes}) : _randomBytes = randomBytes ?? bindings.RandomBytes();

  /// Generates a sequence of [size] random numbers
  UnmodifiableUint8ListView buffer(int size) {
    return freeZero1(
      Uint8Array.allocate(count: size),
      (bufPtr) {
        _randomBytes.buffer(bufPtr.rawPtr.cast<Void>(), size);
        return UnmodifiableUint8ListView(Uint8List.fromList(bufPtr.view));
      },
    );
  }

  /// Generates a sequence of [size] pseudo-random numbers.
  /// [seed] must be [sealBytes] long. The same [seed] produces the same
  /// sequence of pseudo-random numbers.
  UnmodifiableUint8ListView bufferDeterministic(int size, Uint8List seed) {
    return free1freeZero1(
      seed.asArray,
      Uint8Array.allocate(count: size),
      (seedPtr, bufPtr) {
        _randomBytes.deterministic(bufPtr.rawPtr.cast(), size, seedPtr.rawPtr);
        return UnmodifiableUint8ListView(Uint8List.fromList(bufPtr.view));
      },
    );
  }
}
