import 'dart:typed_data';
import 'dart:ffi';

import 'package:ffi_helper/ffi_helper.dart';
import 'internal_helpers.dart';

import 'bindings/generic_hash.dart' as bindings;

class GenericHashError extends Error {
  @override
  String toString() {
    return 'Generating generic hash failed';
  }
}

class InitStreamError extends Error {
  @override
  String toString() {
    return 'Initializing generic hash stream failed';
  }
}

class UpdateStreamError extends Error {
  @override
  String toString() {
    return 'Updating generic hash stream failed';
  }
}

class FinalizeStreamError extends Error {
  @override
  String toString() {
    return 'Finalize generic hash stream failed';
  }
}

/// Generate a fingerprint for [input]. A different [key] (optional) produces
/// a different fingerprint for the same [input]. [key] (when provided) must be between
/// [keyBytesMin] and [keyBytesMax] long (recommended [keyBytes]). [outLength] (optional) controls
/// the length of the generated hash and must be between [genericHashBytesMin] and [genericHashBytesMax] long (standart [genericHashBytes]).
///
/// Please remember to use constant-time comparison when comparing two fingerprints.
Uint8List genericHash(Uint8List input, {Uint8List key, int outLength}) {
  assert(key == null
      ? true
      : key.length >= bindings.keyBytesMin &&
          key.length <= bindings.keyBytesMax);
  assert(outLength == null
      ? true
      : outLength >= bindings.genericHashBytesMin &&
          outLength <= bindings.genericHashBytesMax);
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
    throw GenericHashError();
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

  /// The same [key] results in the same fingerprint just as calling [GenericHashStream]
  /// without any [key] at all. But a different [key] will also result in a different
  /// fingerprint. When [key] is provided it must be between [keyBytesMin] and [keyBytesMax]
  /// long (recommended is [keyBytes]). [outhLength] controls the length of the resulting hash
  /// and must be between [genericHashBytesMin] and [genericHashBytesMax] (standard is [genericHashBytes]).
  /// Throws [InitStreamError] when initializing stream fails.
  factory GenericHashStream({Uint8List key, int outLength}) {
    assert(key == null
        ? true
        : key.length >= bindings.keyBytesMin &&
            key.length <= bindings.keyBytesMax);
    assert(outLength == null
        ? true
        : outLength >= bindings.genericHashBytesMin &&
            outLength <= bindings.genericHashBytesMax);
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
      throw InitStreamError();
    }
    return GenericHashStream.resume(state, outLength);
  }

  /// Updates the stream with [input]. Call [update] of every part of the message.
  /// Throws [UpdateStreamError] when updating stream fails.
  void update(Uint8List input) {
    final statePtr = Uint8Array.fromTypedList(_state);
    final inPtr = Uint8Array.fromTypedList(input);

    final result = bindings.update(statePtr.rawPtr, inPtr.rawPtr, input.length);
    _state.setAll(0, statePtr.view);
    statePtr.freeZero();
    inPtr.free();

    if (result != 0) {
      throw UpdateStreamError();
    }
  }

  /// Generates the fingerprint of the multi-part message.
  /// The stream mustn't be used after calling [finalize].
  /// Throws [FinalizeStreamError] when finalizing fails.
  Uint8List finalize() {
    final statePtr = Uint8Array.fromTypedList(_state);
    final outPtr = Uint8Array.allocate(count: outLength);

    final result = bindings.finish(statePtr.rawPtr, outPtr.rawPtr, outLength);
    statePtr.freeZero();
    outPtr.free();

    if (result != 0) {
      throw FinalizeStreamError();
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
