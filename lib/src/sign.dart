import 'dart:ffi';
import 'dart:typed_data';

import 'package:dart_sodium/src/bindings/secure_memory.dart';

import 'bindings/sign.dart' as bindings;
import 'box.dart';
import 'ffi_helper.dart';

/// Sign messages with a shared key
class Signer {
  static final secretKeyBytes = bindings.secretKeyBytes;
  static final publicKeyBytes = bindings.publicKeyBytes;

  /// Generates a secret and public [KeyPair]
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
      final publicKey = CStringToBuffer(publicKeyPtr, bindings.publicKeyBytes);
      return KeyPair(publicKey, secretKey);
    } finally {
      secretKeyPtr.free();
      publicKeyPtr.free();
    }
  }

  /// Checks the authenticity of [signedMsg] (signed with [sign]) with the [publicKey]
  /// and returns only the message
  static Uint8List open(Uint8List signedMsg, Uint8List publicKey) {
    if (publicKey.length != bindings.publicKeyBytes) {
      throw ArgumentError("Public Key hasn't expected length");
    }
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

  final Pointer<Uint8> _secretKey;
  Signer(Uint8List secretKey) : this._secretKey = BufferToCString(secretKey) {
    if (secretKey.length != bindings.secretKeyBytes) {
      close();
      throw ArgumentError("Secret Key hasn't expected length");
    }
    memoryLock(_secretKey.address, bindings.secretKeyBytes);
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

  void close() {
    memoryUnlock(_secretKey.address, bindings.secretKeyBytes);
    _secretKey.free();
  }
}

/// Signs big messages that couldn't fit into memory
/// or messages that are received chunked
///
/// UNSTABLE: Don't use it for the time being.
class UnstableStreamSigner {
  final Pointer<bindings.State> _state;
  final Pointer<Uint8> _secretKey;
  UnstableStreamSigner(Uint8List secretKey)
      : _secretKey = BufferToCString(secretKey),
        _state = allocate(count: bindings.stateBytes) {
    if (secretKey.length != bindings.secretKeyBytes) {
      close();
      throw ArgumentError("Secret Key hasn't expected length");
    }
    final result = bindings.signInit(_state);
    if (result != 0) {
      close();
      throw ArgumentError("Initializing StreamSigner failed");
    }
    memoryLock(_secretKey.address, bindings.secretKeyBytes);
    memoryLock(_state.address, bindings.stateBytes);
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
    final Pointer<Uint64> sigLenPtr = allocate();
    try {
      final result = bindings.signFinal(_state, sigPtr, sigLenPtr, _secretKey);
      if (result != 0) {
        throw Exception("Signing message failed");
      }
      final sigLen = sigLenPtr.load<int>();
      return CStringToBuffer(sigPtr, sigLen);
    } finally {
      sigPtr.free();
    }
  }

  /// Verifies the authenticity of a [signature] with the [publicKey]
  bool verify(Uint8List signature, Uint8List publicKey) {
    if (publicKey.length != bindings.publicKeyBytes) {
      throw ArgumentError("[publicKey] hasn't expected length");
    }
    if (signature.length != bindings.signBytes) {
      throw ArgumentError("[signature] hasn't expected length");
    }
    final sigPtr = BufferToCString(signature);
    final pkPtr = BufferToCString(publicKey);
    try {
      final result = bindings.signFinalVerify(_state, sigPtr, pkPtr);
      return result == 0;
    } finally {
      sigPtr.free();
      pkPtr.free();
    }
  }

  /// Closes [UnstableStreamSigner]
  void close() {
    memoryUnlock(_secretKey.address, bindings.secretKeyBytes);
    memoryUnlock(_state.address, bindings.stateBytes);
    _state.free();
    _secretKey.free();
  }
}
