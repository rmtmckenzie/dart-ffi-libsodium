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

/// Generates a master key from which subkeys can be derived
UnmodifiableUint8ListView keyGen() {
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes);
  bindings.keyGen(keyPtr.rawPtr);
  final key = UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
  keyPtr.freeZero();

  return key;
}

/// Derives subkey from [key]. [subkeyLength] must be between [subkeyBytesMin] and [subkeyBytesMax] long.
/// [key] must be [keyBytes] long.
/// [context] must be 8 bytes long and describes the domain the subkey is used for (eg '__auth__').
/// [subkeyId] is the n-th generated subkey.
/// Up to 2^64 subkeys per [key] and [context] can be safely generated.
UnmodifiableUint8ListView deriveFromKey(
    int subkeyLength, int subkeyId, Uint8List context, Uint8List key) {
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
    checkExpectedArgument(key.length, bindings.keyBytes, 'key.length');
    checkExpectedArgument(
        context.length, bindings.contextBytes, 'context.length');
    if (subkeyLength > bindings.subkeyBytesMax ||
        subkeyLength < bindings.subkeyBytesMin) {
      throw RangeError.range(subkeyLength, bindings.subkeyBytesMin,
          bindings.subkeyBytesMax, 'subkeyLength');
    }
    throw Error();
  }
  return subkey;
}

/// Wrapper around [deriveFromKey] which automatically increases the [subkeyId]
class SubkeyGenerator {
  final UnmodifiableUint8ListView context, key;
  int _subkeyId;
  int get subkeyId => _subkeyId;

  SubkeyGenerator(Uint8List context, Uint8List key, [this._subkeyId = 0])
      : context = UnmodifiableUint8ListView(context),
        key = UnmodifiableUint8ListView(key);

  UnmodifiableUint8ListView next(int subkeyLength) {
    final subkey = deriveFromKey(subkeyLength, _subkeyId, context, key);
    _subkeyId++;
    return subkey;
  }
}

/// Nonce extension for ciphers with a nonce shorter than 192 bits.
/// It derives a subkey of [key] with a 192 bits long [nonce]. [key] must be 32 bytes long.
/// Now you can use the subkey for encryption and shorten the [nonce] to the required length.
/// This way the [nonce] can be safely randomly generated for ciphers with short nonces.
/// Optionally a 16 bytes [constant] can be provided to make the function unique
/// for one machine or process.
UnmodifiableUint8ListView hchacha20(Uint8List nonce, Uint8List key,
    [Uint8List constant]) {
  final inputPtr = Uint8Array.fromTypedList(nonce);
  final outPtr = Uint8Array.allocate(count: 32);
  final keyPtr = Uint8Array.fromTypedList(key);

  final constPtr = constant == null
      ? nullptr.cast<Pointer<Uint8>>()
      : Uint8Array.fromTypedList(constant).rawPtr;

  final result = bindings.hchacha20(
      outPtr.rawPtr, inputPtr.rawPtr, keyPtr.rawPtr, constPtr);
  keyPtr.freeZero();
  inputPtr.free();
  free(constPtr);
  final out = UnmodifiableUint8ListView(Uint8List.fromList(outPtr.view));
  outPtr.freeZero();
  if (result != 0) {
    checkExpectedArgument(nonce.length, 16, 'nonce.length');
    checkExpectedArgument(key.length, 32, 'key.length');
    constant ?? checkExpectedArgument(constant.length, 16, 'constant.length');
  }
  return out;
}
