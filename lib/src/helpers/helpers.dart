import 'dart:typed_data';

import '../bindings/libsodium.dart';
import 'internal_helpers.dart';

class Helpers {
  final LibSodium _bindings;

  Helpers([LibSodium _bindings]) : _bindings = _bindings ?? LibSodium();

  bool memoryCompare(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      throw ArgumentError('Both arguments must have the same length');
    }

    return free2(
      a.asArray,
      b.asArray,
      (aPtr, bPtr) {
        return _bindings.memoryCompare(aPtr.rawPtr.cast(), bPtr.rawPtr.cast(), a.length) == 0;
      },
    );
  }
}
