import 'dart:ffi';
import 'dart:typed_data';
import 'bindings/secure_memory.dart';

import 'ffi_helper.dart';

import 'bindings/box.dart' as bindings;

class KeyPair {
  final Uint8List publicKey, secretKey;
  const KeyPair(this.publicKey, this.secretKey);
}

class Detached {
  final Uint8List ciphertext, authTag;
  const Detached(this.ciphertext, this.authTag);
}

/// Encrypt and decrypt single messages
class Box {
  /// Required length of the [secretKey]
  static final secretKeyBytes = bindings.secretKeyBytes;

  /// Required length of the [publicKey]
  static final publicKeyBytes = bindings.publicKeyBytes;

  /// Required length of the [nonce]
  static final nonceBytes = bindings.nonceBytes;

  /// Generates a public and secret [KeyPair]
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
  Box(Uint8List secretKey) : this._secretKey = BufferToCString(secretKey) {
    if (secretKey.length != bindings.secretKeyBytes) {
      close();
      throw ArgumentError("Secret Key hasn't expected length");
    }
    memoryLock(_secretKey.address, bindings.secretKeyBytes);
  }

  /// Encrypts a single message given a unique [nonce] and [publicKey]
  Uint8List easy(Uint8List msg, Uint8List nonce, Uint8List publicKey) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    if (publicKey.length != bindings.publicKeyBytes) {
      throw ArgumentError("[publicKey] hasn't expected length");
    }
    final pkPtr = BufferToCString(publicKey);
    final Pointer<Uint8> msgPtr = BufferToCString(msg);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final cLen = bindings.macBytes + msg.length;
    final Pointer<Uint8> cPtr = allocate(count: cLen);
    try {
      final result =
          bindings.easy(cPtr, msgPtr, msg.length, noncePtr, pkPtr, _secretKey);
      if (result != 0) {
        throw Exception("Encrypting failed");
      }
      return CStringToBuffer(cPtr, cLen);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
      pkPtr.free();
    }
  }

  /// Opens messages encrypted with [easy] given the [nonce]and [publicKey]
  Uint8List openEasy(
      Uint8List ciphertext, Uint8List nonce, Uint8List publicKey) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    if (publicKey.length != bindings.publicKeyBytes) {
      throw ArgumentError("[publicKey] hasn't expected length");
    }
    final pkPtr = BufferToCString(publicKey);
    final msgLen = ciphertext.length - bindings.macBytes;
    final Pointer<Uint8> msgPtr = allocate(count: msgLen);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final Pointer<Uint8> cPtr = BufferToCString(ciphertext);
    try {
      final result = bindings.openEasy(
          msgPtr, cPtr, ciphertext.length, noncePtr, pkPtr, _secretKey);
      if (result != 0) {
        throw Exception("Decrypting failed");
      }
      return CStringToBuffer(msgPtr, msgLen);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
      pkPtr.free();
    }
  }

  /// Encrypts a single message given a unique [nonce] and [publicKey] like [easy],
  /// but the authentication tag and ciphertext are detached from one another
  Detached detached(Uint8List msg, Uint8List nonce, Uint8List publicKey) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    if (publicKey.length != bindings.publicKeyBytes) {
      throw ArgumentError("[publicKey] hasn't expected length");
    }
    final pkPtr = BufferToCString(publicKey);
    final Pointer<Uint8> msgPtr = BufferToCString(msg);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final Pointer<Uint8> cPtr = allocate(count: msg.length);
    final Pointer<Uint8> mac = allocate(count: bindings.macBytes);
    try {
      final result = bindings.detached(
          cPtr, mac, msgPtr, msg.length, noncePtr, pkPtr, _secretKey);
      if (result != 0) {
        throw Exception("Encrypting failed");
      }
      final c = CStringToBuffer(cPtr, msg.length);
      final authTag = CStringToBuffer(mac, bindings.macBytes);
      return Detached(c, authTag);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
      pkPtr.free();
      mac.free();
    }
  }

  /// Opens a message encrypted with [detached] given the [nonce], [authTag] and [publicKey]
  Uint8List openDetached(Uint8List ciphertext, Uint8List nonce,
      Uint8List authTag, Uint8List publicKey) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    if (publicKey.length != bindings.publicKeyBytes) {
      throw ArgumentError("[publicKey] hasn't expected length");
    }
    if (authTag.length != bindings.macBytes) {
      throw ArgumentError("[authTag] hasn't expected length");
    }
    final pkPtr = BufferToCString(publicKey);
    ;
    final Pointer<Uint8> msgPtr = allocate(count: ciphertext.length);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final Pointer<Uint8> cPtr = BufferToCString(ciphertext);
    final Pointer<Uint8> mac = BufferToCString(authTag);
    try {
      final result = bindings.openDetached(
          msgPtr, cPtr, mac, ciphertext.length, noncePtr, pkPtr, _secretKey);
      if (result != 0) {
        throw Exception("Decrypting failed");
      }
      return CStringToBuffer(msgPtr, ciphertext.length);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
      pkPtr.free();
      mac.free();
    }
  }

  /// Closes the box
  void close() {
    memoryUnlock(_secretKey.address, bindings.secretKeyBytes);
    _secretKey.free();
  }
}

/// Encrypt and decrypt several messages for the same receiver or sender.
/// It derives a shared key once and stores it to make it more efficient.
class BoxNumerous {
  final Pointer<Uint8> _key;
  BoxNumerous(Uint8List publicKey, Uint8List secretKey)
      : _key = allocate(count: bindings.beforeNmBytes) {
    if (secretKey.length != bindings.secretKeyBytes) {
      close();
      throw ArgumentError("Secret Key hasn't expected length");
    }
    if (publicKey.length != bindings.publicKeyBytes) {
      close();
      throw ArgumentError("Public Key hasn't expected length");
    }
    final skPtr = BufferToCString(secretKey);
    final pkPtr = BufferToCString(publicKey);
    try {
      final result = bindings.beforeNm(_key, pkPtr, skPtr);
      if (result != 0) {
        close();
        throw Exception("Key generation failed");
      }
      memoryLock(_key.address, bindings.beforeNmBytes);
    } finally {
      skPtr.free();
      pkPtr.free();
    }
  }

  /// Encrypts a single message given a unique [nonce]
  Uint8List easy(Uint8List msg, Uint8List nonce) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    final Pointer<Uint8> msgPtr = BufferToCString(msg);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final cLen = bindings.macBytes + msg.length;
    final Pointer<Uint8> cPtr = allocate(count: cLen);
    try {
      final result =
          bindings.easyAfterNm(cPtr, msgPtr, msg.length, noncePtr, _key);
      if (result != 0) {
        throw Exception("Encrypting failed");
      }
      return CStringToBuffer(cPtr, cLen);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
    }
  }

  /// Decrypts a single message encrypted by [easy] given the [nonce]
  Uint8List openEasy(Uint8List ciphertext, Uint8List nonce) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    final msgLen = ciphertext.length - bindings.macBytes;
    final Pointer<Uint8> msgPtr = allocate(count: msgLen);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final Pointer<Uint8> cPtr = BufferToCString(ciphertext);
    try {
      final result = bindings.openEasyAfterNm(
          msgPtr, cPtr, ciphertext.length, noncePtr, _key);
      if (result != 0) {
        throw Exception("Decrypting failed");
      }
      return CStringToBuffer(msgPtr, msgLen);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
    }
  }

  /// Encrypts a single message given a unique [nonce] like [easy],
  /// but the authentication tag and ciphertext are detached from one another
  Detached detached(Uint8List msg, Uint8List nonce) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    final Pointer<Uint8> msgPtr = BufferToCString(msg);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final Pointer<Uint8> cPtr = allocate(count: msg.length);
    final Pointer<Uint8> mac = allocate(count: bindings.macBytes);
    try {
      final result = bindings.detachedAfterNm(
          cPtr, mac, msgPtr, msg.length, noncePtr, _key);
      if (result != 0) {
        throw Exception("Encrypting failed");
      }
      final c = CStringToBuffer(cPtr, msg.length);
      final authTag = CStringToBuffer(mac, bindings.macBytes);
      return Detached(c, authTag);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
      mac.free();
    }
  }

  /// Opens a message encrypted with [detached] given the [nonce], [authTag] and [publicKey]
  Uint8List openDetached(
      Uint8List ciphertext, Uint8List nonce, Uint8List authTag) {
    if (nonce.length != bindings.nonceBytes) {
      throw ArgumentError("[nonce] hasn't expected length");
    }
    if (authTag.length != bindings.macBytes) {
      throw ArgumentError("[authTag] hasn't expected length");
    }
    final Pointer<Uint8> msgPtr = allocate(count: ciphertext.length);
    final Pointer<Uint8> noncePtr = BufferToCString(nonce);
    final Pointer<Uint8> cPtr = BufferToCString(ciphertext);
    final Pointer<Uint8> mac = BufferToCString(authTag);
    try {
      final result = bindings.openDetachedAfterNm(
          msgPtr, cPtr, mac, ciphertext.length, noncePtr, _key);
      if (result != 0) {
        throw Exception("Decrypting failed");
      }
      return CStringToBuffer(msgPtr, ciphertext.length);
    } finally {
      msgPtr.free();
      noncePtr.free();
      cPtr.free();
      mac.free();
    }
  }

  /// Closes the box
  void close() {
    memoryUnlock(_key.address, bindings.beforeNmBytes);
    _key.free();
  }
}
