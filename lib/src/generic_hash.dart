import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/generic_hash.dart' as bindings;
import 'internal_helpers.dart';

/// {@template dart_sodium_generichash_arguments}
/// A different [key] (optional) produces
/// a different fingerprint for the same [input]. [key] (when provided) must be between
/// [keyBytesMin] and [keyBytesMax] long (recommended [keyBytes]). [outLength] (optional) controls
/// the length of the generated hash and must be between [genericHashBytesMin] and [genericHashBytesMax] long (standart [genericHashBytes]).
/// {@endtemplate}

mixin _ArgChecker {
  bindings.GenericHash get _bindings;

  void _checkGenericHashArguments(Uint8List key, int outLength) {
    if (key != null && (key.length < _bindings.keyBytesMin || key.length > _bindings.keyBytesMax)) {
      throw ArgumentError.value(key.length, 'key.length', 'must be between "${_bindings.keyBytesMin}" and "${_bindings.keyBytesMax}"');
    }
    if (outLength > _bindings.genericHashBytesMax || outLength < _bindings.genericHashBytesMin) {
      throw ArgumentError.value(outLength, 'outLength', 'must be between "${_bindings.genericHashBytesMax}" and "${_bindings.genericHashBytesMin}"');
    }
  }
}

class GenericHash with _ArgChecker {
  @override
  final bindings.GenericHash _bindings;

  GenericHash([bindings.GenericHash _bindings]) : _bindings = _bindings ?? bindings.GenericHash();

  /// Generate a fingerprint for [input]. {@macro dart_sodium_generichash_arguments}
  /// Please remember to use constant-time comparison when comparing two fingerprints (see [memoryCompare]).
  Uint8List genericHash(Uint8List input, {Uint8List key, int outLength}) {
    if (outLength != null) {
      _checkGenericHashArguments(key, outLength);
    } else {
      outLength = _bindings.genericHashBytes;
    }

    if (key == null) {
      return free2(
        Uint8Array.allocate(count: outLength),
        input.asArray,
        (outPtr, inPtr) {
          final result = _bindings.genericHash(outPtr.rawPtr, outLength, inPtr.rawPtr, input.length, nullptr.cast(), 0);
          if (result != 0) {
            throw Error();
          }
          return Uint8List.fromList(outPtr.view);
        },
      );
    } else {
      return free2freeZero1(
        Uint8Array.allocate(count: outLength),
        input.asArray,
        key?.asArray,
        (outPtr, inPtr, keyPtr) {
          final result = _bindings.genericHash(outPtr.rawPtr, outLength, inPtr.rawPtr, input.length, keyPtr.rawPtr, key.length);
          if (result != 0) {
            throw Error();
          }
          return Uint8List.fromList(outPtr.view);
        },
      );
    }
  }

  /// Generates a key for generic hash.
  UnmodifiableUint8ListView keyGen() {
    final keyPtr = Uint8Array.allocate(count: _bindings.keyBytes);
    _bindings.keyGen(keyPtr.rawPtr);
    final key = UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
    keyPtr.freeZero();
    return key;
  }

  /// {@macro dart_sodium_generichash_arguments}, and pass in bindings object.
  GenericHashStream stream({Uint8List key, int outLength}) {
    outLength ??= _bindings.genericHashBytes;
    final statePtr = Uint8Array.allocate(count: _bindings.stateBytes);

    var result = 0;
    if (key == null) {
      result = _bindings.init(statePtr.rawPtr, nullptr.cast(), 0, outLength);
    } else {
      final keyPtr = key.asArray;
      result = _bindings.init(statePtr.rawPtr, keyPtr.rawPtr, key.length, outLength);
      keyPtr.freeZero();
    }
    final state = Uint8List.fromList(statePtr.view);
    statePtr.freeZero();

    if (result != 0) {
      _checkGenericHashArguments(key, outLength);
      throw Error();
    }
    return GenericHashStream._resume(state, outLength, _bindings);
  }

  /// Resume stream with a saved [state] and [outhLength];
  GenericHashStream resumeStream(Uint8List state, int outLength) => GenericHashStream._resume(state, outLength, _bindings);
}

/// Generates hash for a multi-part message
class GenericHashStream {
  final int outLength;

  UnmodifiableUint8ListView get state => UnmodifiableUint8ListView(_state);

  final bindings.GenericHash _bindings;
  final Uint8List _state;

  /// Resume stream with a saved [state] and [outhLength], and pass in bindings object;
  GenericHashStream._resume(this._state, this.outLength, this._bindings);

  /// Updates the stream with [input]. Call [update] of every part of the message.
  void update(Uint8List input) {
    free1freeZero1(
      input.asArray,
      _state.asArray,
      (inPtr, statePtr) {
        final result = _bindings.update(statePtr.rawPtr, inPtr.rawPtr, input.length);
        if (result != 0) {
          StateError('GenericHashStream state is bad');
        }

        _state.setAll(0, statePtr.view);
      },
    );
  }

  /// Generates the fingerprint of the multi-part message.
  /// The stream mustn't be used after calling [finalize].
  Uint8List finalize() {
    return free1freeZero1(
      Uint8Array.allocate(count: outLength),
      _state.asArray,
      (outPtr, statePtr) {
        final result = _bindings.finish(statePtr.rawPtr, outPtr.rawPtr, outLength);
        if (result != 0) {
          StateError('GenericHashStream state is bad');
        }
        return Uint8List.fromList(outPtr.view);
      },
    );
  }
}
