import 'bindings/secretbox.dart' as bindings;
import 'package:ffi_helper/ffi_helper.dart';
import 'dart:typed_data';
import 'internal_helpers.dart';
import 'random_bytes.dart' as random;

/// Authenticated encryption of single messages.
class SecretBox {
  static const keyBytes = 32;
  static const nonceBytes = 24;

  /// Generates a key for [SecretBox].
  static UnmodifiableUint8ListView keyGen() {
    final keyPtr = Uint8Array.allocate(count: bindings.keyBytes);
    final key = Uint8List.fromList(keyPtr.view);
    bindings.keyGen(keyPtr.rawPtr);
    keyPtr.view.fillZero();
    keyPtr.free();
    return UnmodifiableUint8ListView(key);
  }

  final UnmodifiableUint8ListView key;
  UnmodifiableUint8ListView nonce;
  SecretBox._(this.key);

  /// If [key] is left empty, a key will be generated.
  /// Otherwise [key] must be [keyBytes] long.
  factory SecretBox([Uint8List key]) {
    if (key == null) {
      key = keyGen();
    } else {
      checkExpectedLengthOf(key.length, bindings.keyBytes, 'key');
    }
    return SecretBox._(UnmodifiableUint8ListView(key));
  }

  /// Encrypts [message] with [key].
  /// If [nonce] is left empty, a nonce will be generated and stored in [SecretBox.nonce].
  /// Otherwise [nonce] must be [nonceBytes] long.
  Uint8List encrypt(Uint8List message, [Uint8List nonce]) {
    if (nonce == null) {
      nonce = random.buffer(24);
      this.nonce = nonce;
    } else {
      checkExpectedLengthOf(nonce.length, bindings.nonceBytes, 'nonce');
    }
    final messagePtr = Uint8Array.fromTypedList(message);
    final noncePtr = Uint8Array.fromTypedList(nonce);
    final keyPtr = Uint8Array.fromTypedList(key);
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
      throw Exception();
    }
    return Uint8List.fromList(ciphertextPtr.view);
  }

  /// Decrypts a message encrypted with [encrypt].
  Uint8List decrypt(Uint8List ciphertext, Uint8List nonce) {
    checkExpectedLengthOf(nonce.length, bindings.nonceBytes, 'nonce');
    final cPtr = Uint8Array.fromTypedList(ciphertext);
    final noncePtr = Uint8Array.fromTypedList(nonce);
    final keyPtr = Uint8Array.fromTypedList(key);
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
      throw Exception();
    }
    return Uint8List.fromList(messagePtr.view);
  }
}
