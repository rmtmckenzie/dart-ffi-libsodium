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
      close();
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
        throw Exception(
            "Open message failed. Signature doesn't seem to be valid");
      }
      return CStringToBuffer(msgPtr, msgLen);
    } finally {
      msgPtr.free();
      signedMsgPtr.free();
    }
  }

  void close() {
    _secretKey.free();
  }
}

/// Signs big messages that couldn't fit into memory
/// or messages that are received chunked
class StreamSigner {
  final Pointer<bindings.State> _state;
  final Pointer<Uint8> _secretKey;
  StreamSigner(Uint8List secretKey)
      : _secretKey = BufferToCString(secretKey),
        _state = allocate(count: bindings.stateBytes) {
    if (secretKey.length != bindings.secretKeyBytes) {
      close();
      throw Exception("Secret Key hasn't expected length");
    }
    final result = bindings.signInit(_state);
    if (result != 0) {
      close();
      throw Exception("Initializing StreamSigner failed");
    }
  }

  /// Push msg into stream
  void update(Uint8List msg) {
    final Pointer<Uint8> msgPtr = BufferToCString(msg);
    try {
      final result = bindings.signUpdate(_state, msgPtr, msg.length);
      if (result != 0) {
        throw Exception("Pushing message into stream failed");
      }
    } finally {
      msgPtr.free();
    }
  }

  /// End stream and generate signature
  Uint8List finish() {
    final Pointer<Uint8> sigPtr = allocate(count: bindings.signBytes);
    try {
      final result = bindings.signFinal(_state, sigPtr, null, _secretKey);
      if (result != 0) {
        throw Exception("Signing message failed");
      }
      return CStringToBuffer(sigPtr, bindings.signBytes);
    } finally {
      sigPtr.free();
    }
  }

  /// Verifies the authenticity of a [signature] with the [publicKey]
  bool verify(Uint8List signature, Uint8List publicKey) {
    final sigPtr = BufferToCString(signature);
    final pkPtr = BufferToCString(publicKey);
    try {
      final result = bindings.signFinalVerify(_state, sigPtr, _secretKey);
      if (result != 0) {
        return false;
      }
      return true;
    } finally {
      sigPtr.free();
      pkPtr.free();
    }
  }

  /// Closes [StreamSigner]
  void close() {
    _state.free();
    _secretKey.free();
  }
}
