import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/box.dart' as bindings;
import 'internal_helpers.dart';
import 'secret_box.dart' show EncryptionError, DecryptionError;

class KeyPairException implements Exception {
  @override
  String toString() {
    return 'Failed to generate key pair';
  }
}

class BeforeNumerousError extends Error {
  @override
  String toString() {
    return 'Generating shared key failed';
  }
}

/// Generates a pair of public- and secret-key.
class KeyPair {
  final UnmodifiableUint8ListView publicKey, secretKey;
  const KeyPair._(this.publicKey, this.secretKey);

  /// Generates a pair of public and secret key.
  /// Throws [KeyPairException] when generating keys fails.
  factory KeyPair.generate() {
    final pkPtr = Uint8Array.allocate(count: bindings.publicKeyBytes);
    final skPtr = Uint8Array.allocate(count: bindings.secretKeyBytes);
    final result = bindings.keyPair(pkPtr.rawPtr, skPtr.rawPtr);
    final publicKey = UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view));
    final secretKey = UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view));
    pkPtr.freeZero();
    skPtr.freeZero();
    if (result != 0) {
      throw KeyPairException();
    }
    return KeyPair._(publicKey, secretKey);
  }

  /// Derives [publicKey] and [secretKey] from [seed].
  /// Throws [KeyPairException] when generating keys fails.
  factory KeyPair.fromSeed(Uint8List seed) {
    final pkPtr = Uint8Array.allocate(count: bindings.publicKeyBytes);
    final skPtr = Uint8Array.allocate(count: bindings.secretKeyBytes);
    final seedPtr = Uint8Array.fromTypedList(seed);
    final result =
        bindings.seedKeyPair(pkPtr.rawPtr, skPtr.rawPtr, seedPtr.rawPtr);
    final publicKey = UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view));
    final secretKey = UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view));

    pkPtr.freeZero();
    skPtr.freeZero();
    if (result != 0) {
      throw KeyPairException();
    }
    return KeyPair._(publicKey, secretKey);
  }
}

void _checkKeyPair(Uint8List publicKey, Uint8List secretKey) {
  checkExpectedArgument(
      publicKey.length, bindings.publicKeyBytes, 'publicKey.length');
  checkExpectedArgument(
      secretKey.length, bindings.secretKeyBytes, 'secretKey.length');
}

void _checkNonce(Uint8List nonce) {
  checkExpectedArgument(nonce.length, bindings.nonceBytes, 'nonce.length');
}

/// Throws [ArgumentError] when arguments for the crypto_box_easy interface
/// are false.
void _checkEasyArguments(
    Uint8List nonce, Uint8List publicKey, Uint8List secretKey) {
  _checkNonce(nonce);
  _checkKeyPair(publicKey, secretKey);
}

/// Encrypts [message] with the recipient's [publicKey] and the senders [secretKey].
/// [publicKey] must be [publicKeyBytes] long; [secretKey] must be [secretKeyBytes] long.
/// [nonce] must be [nonceBytes] long and must be a unique value.
/// Throws [EncryptionError] when encrypting message fails.
Uint8List easy(Uint8List message, Uint8List nonce, Uint8List publicKey,
    Uint8List secretKey) {
  final noncePtr = Uint8Array.fromTypedList(nonce);
  final pkPtr = Uint8Array.fromTypedList(publicKey);
  final skPtr = Uint8Array.fromTypedList(secretKey);
  final cPtr = Uint8Array.allocate(count: message.length + bindings.macBytes)
    ..view.setAll(0, message);

  final result = bindings.easy(cPtr.rawPtr, cPtr.rawPtr, message.length,
      noncePtr.rawPtr, pkPtr.rawPtr, skPtr.rawPtr);

  noncePtr.free();
  cPtr.free();
  pkPtr.freeZero();
  skPtr.freeZero();

  if (result != 0) {
    _checkEasyArguments(nonce, publicKey, secretKey);
    throw Error();
  }
  return Uint8List.fromList(cPtr.view);
}

/// Opens [message] encrypted by [easy].
/// Throws [DecryptionError] when decrypting message fails.
Uint8List openEasy(Uint8List ciphertext, Uint8List nonce, Uint8List publicKey,
    Uint8List secretKey) {
  final noncePtr = Uint8Array.fromTypedList(nonce);
  final pkPtr = Uint8Array.fromTypedList(publicKey);
  final skPtr = Uint8Array.fromTypedList(secretKey);
  final cPtr = Uint8Array.fromTypedList(ciphertext);

  final result = bindings.openEasy(cPtr.rawPtr, cPtr.rawPtr, ciphertext.length,
      noncePtr.rawPtr, pkPtr.rawPtr, skPtr.rawPtr);

  noncePtr.free();
  cPtr.free();
  pkPtr.freeZero();
  skPtr.freeZero();

  if (result != 0) {
    _checkEasyArguments(nonce, publicKey, secretKey);
    throw Error();
  }
  return cPtr.view.sublist(0, ciphertext.length - bindings.macBytes);
}

/// Generates a shared key to improve performance.
/// [publicKey] must be [publicKeyBytes] long; [secretKey] must be [secretKeyBytes] long.
/// Throws [BeforeNumerousError] when computing shared key fails.
Uint8List beforeNumerous(Uint8List publicKey, Uint8List secretKey) {
  final pkPtr = Uint8Array.fromTypedList(publicKey);
  final skPtr = Uint8Array.fromTypedList(secretKey);
  final sharedKeyPtr = Uint8Array.allocate(count: bindings.beforeNumerousBytes);

  final result =
      bindings.beforeNumerous(sharedKeyPtr.rawPtr, pkPtr.rawPtr, skPtr.rawPtr);

  pkPtr.freeZero();
  skPtr.freeZero();
  final sharedKey =
      UnmodifiableUint8ListView(Uint8List.fromList(sharedKeyPtr.view));
  sharedKeyPtr.freeZero();

  if (result != 0) {
    _checkKeyPair(publicKey, secretKey);
    throw Error();
  }
  return sharedKey;
}

/// Encrypts [message] with a shared key generated by [beforeNumerous].
/// [nonce] must be [nonceBytes] long and must bea unique value.
/// Throws [EncryptionError] when encrypting [message] fails.
Uint8List easyAfterNumerous(Uint8List message, Uint8List nonce, Uint8List key) {
  assert(nonce.length == bindings.nonceBytes);
  assert(key.length == bindings.beforeNumerousBytes);
  final noncePtr = Uint8Array.fromTypedList(nonce);
  final keyPtr = Uint8Array.fromTypedList(key);
  final cPtr = Uint8Array.allocate(count: message.length + bindings.macBytes)
    ..view.setAll(0, message);

  final result = bindings.easyAfterNumerous(
      cPtr.rawPtr, cPtr.rawPtr, message.length, noncePtr.rawPtr, keyPtr.rawPtr);

  noncePtr.free();
  cPtr.free();
  keyPtr.freeZero();

  if (result != 0) {
    throw EncryptionError();
  }
  return Uint8List.fromList(cPtr.view);
}

/// Decrypts [ciphertext] generated by [easyAfterNumerous].
/// Throws [DecryptionError] when decrypting message fails.
Uint8List openEasyAfterNumerous(
    Uint8List ciphertext, Uint8List nonce, Uint8List key) {
  assert(nonce.length == bindings.nonceBytes);
  assert(key.length == bindings.beforeNumerousBytes);
  final noncePtr = Uint8Array.fromTypedList(nonce);
  final keyPtr = Uint8Array.fromTypedList(key);
  final cPtr = Uint8Array.fromTypedList(ciphertext);

  final result = bindings.openEasyAfterNumerous(cPtr.rawPtr, cPtr.rawPtr,
      ciphertext.length, noncePtr.rawPtr, keyPtr.rawPtr);
  noncePtr.free();
  cPtr.free();
  keyPtr.freeZero();

  if (result != 0) {
    throw DecryptionError();
  }
  return cPtr.view.sublist(0, ciphertext.length - bindings.macBytes);
}
