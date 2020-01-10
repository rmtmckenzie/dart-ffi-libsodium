import 'dart:typed_data';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
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

class FinishStreamError extends Error {
  @override
  String toString() {
    return 'Finish generic hash stream failed';
  }
}

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
    throw GenericHashError();
  }
  return Uint8List.fromList(outPtr.view);
}

class GenericHashStream {
  final Uint8List _state;
  UnmodifiableUint8ListView get stet => UnmodifiableUint8ListView(_state);
  final int outLength;

  GenericHashStream.resume(this._state, this.outLength);
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
      throw InitStreamError();
    }
    return GenericHashStream.resume(state, outLength);
  }
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

  Uint8List finalize() {
    final statePtr = Uint8Array.fromTypedList(_state);
    final outPtr = Uint8Array.allocate(count: outLength);

    final result = bindings.finish(statePtr.rawPtr, outPtr.rawPtr, outLength);
    statePtr.freeZero();
    outPtr.free();

    if (result != 0) {
      throw FinishStreamError();
    }
    return Uint8List.fromList(outPtr.view);
  }
}

UnmodifiableUint8ListView keyGen() {
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes);
  bindings.keyGen(keyPtr.rawPtr);
  final key = UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
  keyPtr.freeZero();
  return key;
}
