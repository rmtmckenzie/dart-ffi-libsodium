import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/key_derivation.dart' as bindings;
import 'helpers/internal_helpers.dart';

class KeyDerivationError extends Error {
  @override
  String toString() {
    return 'Failed to derive key';
  }
}

class KeyDerivation {
  final bindings.KeyDerivation _bindings;

  KeyDerivation([bindings.KeyDerivation _bindings]) : _bindings = _bindings ?? bindings.KeyDerivation();

  /// Generates a master key from which subkeys can be derived
  UnmodifiableUint8ListView keyGen() {
    return freeZero1(Uint8Array.allocate(count: _bindings.keyBytes), (keyPtr) {
      _bindings.keyGen(keyPtr.rawPtr);
      return UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
    });
  }

  /// Derives subkey from [key]. [subkeyLength] must be between [subkeyBytesMin] and [subkeyBytesMax] long.
  /// [key] must be [keyBytes] long.
  /// [context] must be 8 bytes long and describes the domain the subkey is used for (eg '__auth__').
  /// [subkeyId] is the n-th generated subkey.
  /// Up to 2^64 subkeys per [key] and [context] can be safely generated.
  UnmodifiableUint8ListView deriveFromKey(int subkeyLength, int subkeyId, Uint8List context, Uint8List key) {
    checkExpectedLengthOf(key.length, _bindings.keyBytes, 'key.length');
    checkExpectedLengthOf(context.length, _bindings.contextBytes, 'context.length');
    if (subkeyLength > _bindings.subkeyBytesMax || subkeyLength < _bindings.subkeyBytesMin) {
      throw RangeError.range(subkeyLength, _bindings.subkeyBytesMin, _bindings.subkeyBytesMax, 'subkeyLength');
    }

    return free1freeZero2(
      Uint8Array.allocate(count: subkeyLength),
      context.asArray,
      key.asArray,
      (subkeyPtr, contextPtr, keyPtr) {
        final result =
            _bindings.deriveFromKey(subkeyPtr.rawPtr, subkeyLength, subkeyId, contextPtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw Error();
        }
        return UnmodifiableUint8ListView(Uint8List.fromList(subkeyPtr.view));
      },
    );
  }

  /// Nonce extension for ciphers with a nonce shorter than 192 bits.
  /// It derives a subkey of [key] with a 192 bits long [nonce]. [key] must be 32 bytes long.
  /// Now you can use the subkey for encryption and shorten the [nonce] to the required length.
  /// This way the [nonce] can be safely randomly generated for ciphers with short nonces.
  /// Optionally a 16 bytes [constant] can be provided to make the function unique
  /// for one machine or process.
  UnmodifiableUint8ListView hchacha20(Uint8List nonce, Uint8List key, [Uint8List constant]) {
    checkExpectedLengthOf(nonce.length, 16, 'nonce.length');
    checkExpectedLengthOf(key.length, 32, 'key.length');

    if (constant != null) {
      checkExpectedLengthOf(constant.length, 16, 'constant.length');
      return free2freeZero2(
        nonce.asArray,
        constant.asArray,
        Uint8Array.allocate(count: 32),
        key.asArray,
        (inputPtr, constPtr, outPtr, keyPtr) {
          final result = _bindings.hchacha20(outPtr.rawPtr, inputPtr.rawPtr, keyPtr.rawPtr, constPtr.rawPtr);
          if (result != 0) {
            throw Exception();
          }
          return UnmodifiableUint8ListView(Uint8List.fromList(outPtr.view));
        },
      );
    } else {
      return free1freeZero2(
        nonce.asArray,
        Uint8Array.allocate(count: 32),
        key.asArray,
        (inputPtr, outPtr, keyPtr) {
          final result = _bindings.hchacha20(outPtr.rawPtr, inputPtr.rawPtr, keyPtr.rawPtr, nullptr.cast<Uint8>());
          if (result != 0) {
            throw Exception();
          }
          return UnmodifiableUint8ListView(Uint8List.fromList(outPtr.view));
        },
      );
    }
  }

  SubkeyGenerator subkeyGenerator(Uint8List context, Uint8List key, [subkeyId = 0]) {
    return SubkeyGenerator._(context, key, subkeyId, this);
  }
}

/// Wrapper around [deriveFromKey] which automatically increases the [subkeyId]
class SubkeyGenerator {
  final UnmodifiableUint8ListView context, key;
  final KeyDerivation _keyDerivation;
  int _subkeyId;

  int get subkeyId => _subkeyId;

  SubkeyGenerator._(Uint8List context, Uint8List key, this._subkeyId, this._keyDerivation)
      : context = UnmodifiableUint8ListView(context),
        key = UnmodifiableUint8ListView(key);

  UnmodifiableUint8ListView next(int subkeyLength) {
    final subkey = _keyDerivation.deriveFromKey(subkeyLength, _subkeyId, context, key);
    _subkeyId++;
    return subkey;
  }
}
