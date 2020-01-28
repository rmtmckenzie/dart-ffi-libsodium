import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/key_derivation.dart' as bindings;
import 'internal_helpers.dart';

class KeyDerivationError extends Error {
  @override
  String toString() {
    return 'Failed to derive key';
  }
}

UnmodifiableUint8ListView keyGen() {
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes);
  bindings.keyGen(keyPtr.rawPtr);
  final key = UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
  keyPtr.freeZero();

  return key;
}

UnmodifiableUint8ListView deriveFromKey(
    int subkeyLength, int subkeyId, Uint8List context, Uint8List key) {
  assert(key.length == bindings.keyBytes);
  assert(context.length <= bindings.contextBytes);
  assert(subkeyLength <= bindings.subkeyBytesMax &&
      subkeyLength >= bindings.subkeyBytesMin);
  final subkeyPtr = Uint8Array.allocate(count: subkeyLength);
  final contextPtr = Uint8Array.fromTypedList(context);
  final keyPtr = Uint8Array.fromTypedList(key);
  final result = bindings.deriveFromKey(subkeyPtr.rawPtr, subkeyLength,
      subkeyId, contextPtr.rawPtr, keyPtr.rawPtr);

  final subkey = UnmodifiableUint8ListView(Uint8List.fromList(subkeyPtr.view));
  subkeyPtr.freeZero();
  keyPtr.freeZero();
  contextPtr.free();

  if (result != 0) {
    throw KeyDerivationError();
  }
  return subkey;
}

UnmodifiableUint8ListView hchacha20(Uint8List input, Uint8List key,
    [Uint8List constant]) {
  assert(input.length == 16);
  assert(key.length == 32);
  assert(constant == null ? true : constant.length == 16);
  final inputPtr = Uint8Array.fromTypedList(input);
  final outPtr = Uint8Array.allocate(count: 32);
  final keyPtr = Uint8Array.fromTypedList(key);

  final Pointer<Uint8> constPtr =
      constant == null ? nullptr.cast() : allocate(count: constant.length);
  constPtr.asTypedList(constant.length).setAll(0, constant);

  final result = bindings.hchacha20(
      outPtr.rawPtr, inputPtr.rawPtr, keyPtr.rawPtr, constPtr);
  keyPtr.freeZero();
  inputPtr.free();
  free(constPtr);
  final out = UnmodifiableUint8ListView(Uint8List.fromList(outPtr.view));
  outPtr.freeZero();
  if (result != 0) {
    throw KeyDerivationError();
  }
  return out;
}
