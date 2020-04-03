import 'dart:typed_data';
import 'dart:ffi';

import 'package:ffi_helper/ffi_helper.dart';
import 'internal_helpers.dart';

import 'bindings/generic_hash.dart' as bindings;

/// {@template dart_sodium_generichash_arguments}
/// A different [key] (optional) produces
/// a different fingerprint for the same [input]. [key] (when provided) must be between
/// [keyBytesMin] and [keyBytesMax] long (recommended [keyBytes]). [outLength] (optional) controls
/// the length of the generated hash and must be between [genericHashBytesMin] and [genericHashBytesMax] long (standart [genericHashBytes]).
/// {@endtemplate}

void _checkGenericHashArguments(Uint8List key, int outLength) {
  if (key != null &&
      (key.length < bindings.keyBytesMin ||
          key.length > bindings.keyBytesMax)) {
    throw ArgumentError.value(key.length, 'key.length',
        'must be between "${bindings.keyBytesMin}" and "${bindings.keyBytesMax}"');
  }
  if (outLength > bindings.genericHashBytesMax ||
      key.length < bindings.genericHashBytesMin) {
    throw ArgumentError.value(outLength, 'outLength',
        'must be between "${bindings.genericHashBytesMax}" and "${bindings.genericHashBytesMin}"');
  }
}

/// Generate a fingerprint for [input]. {@macro dart_sodium_generichash_arguments}
/// Please remember to use constant-time comparison when comparing two fingerprints.
Uint8List genericHash(Uint8List input, {Uint8List key, int outLength}) {
  outLength ??= bindings.genericHashBytes;
  final outPtr = Uint8Array.allocate(count: outLength);
  final inPtr = Uint8Array.fromTypedList(input);

  var result = 0;
  if (key == null) {
    result = bindings.genericHash(outPtr.rawPtr, outLength, inPtr.rawPtr,
        input.length, nullptr.cast(), 0);
  } else {
    final keyPtr = Uint8Array.fromTypedList(key);
    result = bindings.genericHash(outPtr.rawPtr, outLength, inPtr.rawPtr,
        input.length, keyPtr.rawPtr, key.length);
    keyPtr.freeZero();
  }
  outPtr.free();
  inPtr.free();

  if (result != 0) {
    _checkGenericHashArguments(key, outLength);
    throw Error();
  }
  return Uint8List.fromList(outPtr.view);
}

/// Generates hash for a multi-part message
class GenericHashStream {
  final Uint8List _state;
  UnmodifiableUint8ListView get state => UnmodifiableUint8ListView(_state);
  final int outLength;

  /// Resume stream with a saved [state] and [outhLength];
  GenericHashStream.resume(this._state, this.outLength);

  /// {@macro dart_sodium_generichash_arguments}
  factory GenericHashStream({Uint8List key, int outLength}) {
    outLength ??= bindings.genericHashBytes;
    final statePtr = Uint8Array.allocate(count: bindings.stateBytes);

    var result = 0;
    if (key == null) {
      result = bindings.init(statePtr.rawPtr, nullptr.cast(), 0, outLength);
    } else {
      final keyPtr = Uint8Array.fromTypedList(key);
      result =
          bindings.init(statePtr.rawPtr, keyPtr.rawPtr, key.length, outLength);
      keyPtr.freeZero();
    }
    final state = Uint8List.fromList(statePtr.view);
    statePtr.freeZero();

    if (result != 0) {
      _checkGenericHashArguments(key, outLength);
      throw Error();
    }
    return GenericHashStream.resume(state, outLength);
  }

  /// Updates the stream with [input]. Call [update] of every part of the message.
  void update(Uint8List input) {
    final statePtr = Uint8Array.fromTypedList(_state);
    final inPtr = Uint8Array.fromTypedList(input);

    final result = bindings.update(statePtr.rawPtr, inPtr.rawPtr, input.length);
    _state.setAll(0, statePtr.view);
    statePtr.freeZero();
    inPtr.free();

    if (result != 0) {
      StateError('GenericHashStream state is bad');
    }
  }

  /// Generates the fingerprint of the multi-part message.
  /// The stream mustn't be used after calling [finalize].
  Uint8List finalize() {
    final statePtr = Uint8Array.fromTypedList(_state);
    final outPtr = Uint8Array.allocate(count: outLength);

    final result = bindings.finish(statePtr.rawPtr, outPtr.rawPtr, outLength);
    statePtr.freeZero();
    outPtr.free();

    if (result != 0) {
      StateError('GenericHashStream state is bad');
    }
    return Uint8List.fromList(outPtr.view);
  }
}

/// Generates a key for generic hash.
UnmodifiableUint8ListView keyGen() {
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes);
  bindings.keyGen(keyPtr.rawPtr);
  final key = UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
  keyPtr.freeZero();
  return key;
}
