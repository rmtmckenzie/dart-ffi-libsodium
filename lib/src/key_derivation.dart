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
/// [context] must be 8 bytes long and describes what the subkey is used for.
/// This way generated subkeys for two different domains will likely be different,
/// even when using the same [key].
/// Up to 2^64 subkeys per [key] and [context] can be safely generated.
/// [subkeyId] is the n-th generated subkey.
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

/// Nonce extension for ciphers with a nonce shorter than 192 bits.
/// It derives a subkey of [key] with a long 192 bits long [nonce]. [key] must be 32 bytes long.
/// Now you can use the subkey for encryption and shorten the [nonce] to the required length.
/// This way the [nonce] can be safely randomly generated for ciphers with short nonces.
/// Optionally a 16 bytes [constant] can be provided to make the function unique
/// for one machine or process.
UnmodifiableUint8ListView hchacha20(Uint8List nonce, Uint8List key,
    [Uint8List constant]) {
  assert(nonce.length == 16);
  assert(key.length == 32);
  assert(constant == null ? true : constant.length == 16);
  final inputPtr = Uint8Array.fromTypedList(nonce);
  final outPtr = Uint8Array.allocate(count: 32);
  final keyPtr = Uint8Array.fromTypedList(key);

  final Pointer<Uint8> constPtr = constant == null
      ? nullptr.cast()
      : Uint8Array.fromTypedList(constant).rawPtr;

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
