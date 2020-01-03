import 'bindings/secretbox.dart' as bindings;
import 'package:ffi_helper/ffi_helper.dart';
import 'dart:typed_data';
import 'helper.dart';

class EncryptionError extends Error {
  @override
  String toString() {
    return 'Failed to encrypt message';
  }
}

class DecryptionError extends Error {
  @override
  String toString() {
    return 'Failed to decrypt message';
  }
}

/// Generates a key for a secret box.
UnmodifiableUint8ListView keyGen() {
  final key = Uint8Array.allocate(count: bindings.keyBytes);
  bindings.keyGen(key.rawPtr);
  key.view.fillZero();
  key.free();
  return UnmodifiableUint8ListView(Uint8List.fromList(key.view));
}

/// Encrypts [message] with [key]. [key] must be [keyBytes] long.
/// [nonce] must a unique value and must be [nonceBytes] long.
/// Throws [EncryptionError] when encryption fails.
Uint8List easy(Uint8List message, Uint8List nonce, Uint8List key) {
  final messagePtr = Uint8Array.fromTypedList(message);
  final noncePtr = Uint8Array.allocate(count: bindings.nonceBytes)
    ..view.setAll(0, nonce);
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes)
    ..view.setAll(0, key);
  final ciphertextPtr =
      Uint8Array.allocate(count: message.length + bindings.macBytes);
  final result = bindings.easy(ciphertextPtr.rawPtr, messagePtr.rawPtr,
      message.length, noncePtr.rawPtr, keyPtr.rawPtr);
  messagePtr.free();
  noncePtr.free();
  keyPtr.view.fillZero();
  keyPtr.free();
  ciphertextPtr.free();
  if (result != 0) {
    throw EncryptionError();
  }
  return Uint8List.fromList(ciphertextPtr.view);
}

/// Opens a message encrypted with [easy].
/// Throws [DecryptionError] when decryption fails.
Uint8List openEasy(Uint8List ciphertext, Uint8List nonce, Uint8List key) {
  final cPtr = Uint8Array.fromTypedList(ciphertext);
  final noncePtr = Uint8Array.allocate(count: bindings.nonceBytes)
    ..view.setAll(0, nonce);
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes)
    ..view.setAll(0, key);
  final messagePtr =
      Uint8Array.allocate(count: ciphertext.length - bindings.macBytes);
  final result = bindings.openEasy(messagePtr.rawPtr, cPtr.rawPtr,
      ciphertext.length, noncePtr.rawPtr, keyPtr.rawPtr);
  cPtr.free();
  noncePtr.free();
  keyPtr.view.fillZero();
  keyPtr.free();
  messagePtr.free();
  if (result != 0) {
    throw DecryptionError();
  }
  return Uint8List.fromList(messagePtr.view);
}
