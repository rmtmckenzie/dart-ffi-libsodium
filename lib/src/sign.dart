import 'dart:ffi';
import 'dart:typed_data';

import 'bindings/sign.dart' as bindings;
import 'box.dart';
import 'ffi_helper.dart';

/// Sign messages with a shared key
class Signer {
  static final secretKeyBytes = bindings.secretKeyBytes;
  static final publicKeyBytes = bindings.publicKeyBytes;

  /// Generates a secret and public [keyPair]
  static KeyPair keyPair() {
    final Pointer<Uint8> secretKeyPtr =
        allocate(count: bindings.secretKeyBytes);
    final Pointer<Uint8> publicKeyPtr =
        allocate(count: bindings.publicKeyBytes);
    try {
      final result = bindings.keyPair(publicKeyPtr, secretKeyPtr);
      if (result != 0) {
        throw Exception("Generation of keypair failed");
      }
      final secretKey = CStringToBuffer(secretKeyPtr, bindings.secretKeyBytes);
      final publicKey = CStringToBuffer(secretKeyPtr, bindings.publicKeyBytes);
      return KeyPair(publicKey, secretKey);
    } finally {
      secretKeyPtr.free();
      publicKeyPtr.free();
    }
  }

  final Pointer<Uint8> _secretKey;
  Signer(Uint8List secretKey) : this._secretKey = BufferToCString(secretKey) {
    if (secretKey.length != bindings.secretKeyBytes) {
      throw Exception("Secret Key hasn't expected length");
    }
  }

  /// Prepends a signature to a copy of [msg]
  Uint8List sign(Uint8List msg) {
    final Pointer<Uint8> msgPtr = BufferToCString(msg);
    final signedMsgLen = bindings.signBytes + msg.length;
    final Pointer<Uint8> signedMsgPtr = allocate(count: signedMsgLen);
    try {
      final result =
          bindings.sign(signedMsgPtr, null, msgPtr, msg.length, _secretKey);
      if (result != 0) {
        throw Exception("Signing message failed");
      }
      return CStringToBuffer(signedMsgPtr, signedMsgLen);
    } finally {
      msgPtr.free();
      signedMsgPtr.free();
    }
  }

  /// Checks the authenticity of [signedMsg] (signed with [sign]) with the [publicKey]
  /// and returns only the message
  Uint8List open(Uint8List signedMsg, Uint8List publicKey) {
    final msgLen = signedMsg.length - bindings.signBytes;
    final Pointer<Uint8> msgPtr = allocate(count: msgLen);
    final Pointer<Uint8> signedMsgPtr = BufferToCString(signedMsg);
    final Pointer<Uint8> pkPtr = BufferToCString(publicKey);
    try {
      final result = bindings.signOpen(
          msgPtr, null, signedMsgPtr, signedMsg.length, pkPtr);
      if (result != 0) {
        throw Exception("Signing message failed");
      }
      return CStringToBuffer(msgPtr, msgLen);
    } finally {
      msgPtr.free();
      signedMsgPtr.free();
    }
  }
}
