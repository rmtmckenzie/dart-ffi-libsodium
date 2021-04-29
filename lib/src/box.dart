import 'dart:typed_data';

import 'package:dart_sodium/src/helpers/memory_array.dart';

import 'bindings/box.dart' as bindings;
import 'helpers/internal_helpers.dart';

/// {@template box_throws_generate_keypair_exception}
/// Throws [KeyPairException] when generating keys fails.
/// {@endtemplate}

/// {@template box_keypair_length}
/// [publicKey] must be [publicKeyBytes] long. [secretKey] must be [secretKeyBytes] long.
/// {@endtemplate}

/// {@template box_nonce_length}
/// [nonce] must be [nonceBytes] long and an unique value.
/// {@endtemplate}

class GenerateKeyPairException implements Exception {
  @override
  String toString() {
    return 'Failed to generate key pair';
  }
}

/// Pair of public- and secret-key.
class KeyPair {
  final UnmodifiableUint8ListView publicKey, secretKey;

  const KeyPair._(this.publicKey, this.secretKey);

  /// Generates a pair of public and secret key.
  /// {@macro box_throws_generate_keypair_exception}
  factory KeyPair([bindings.Box box]) {
    final _box = box ?? bindings.Box();

    return freeZero2(
      Uint8Array.allocate(count: _box.publicKeyBytes),
      Uint8Array.allocate(count: _box.secretKeyBytes),
      (pkPtr, skPtr) {
        if (_box.keyPair(pkPtr.rawPtr, skPtr.rawPtr) != 0) {
          throw GenerateKeyPairException();
        }
        return KeyPair._(UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view)),
            UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view)));
      },
    );
  }

  /// Derives [publicKey] and [secretKey] from [seed].
  /// {@macro dart_sodium_throw_generate_keypair_exception}
  factory KeyPair.fromSeed(Uint8List seed, [bindings.Box box]) {
    final _box = box ?? bindings.Box();
    checkExpectedLengthOf(seed.length, _box.seedBytes, 'seed');

    return free1freeZero2(
        seed.asArray, Uint8Array.allocate(count: _box.publicKeyBytes), Uint8Array.allocate(count: _box.secretKeyBytes),
        (seedPtr, pkPtr, skPtr) {
      final result = _box.seedKeyPair(pkPtr.rawPtr, skPtr.rawPtr, seedPtr.rawPtr);
      if (result != 0) {
        throw GenerateKeyPairException();
      }
      return KeyPair._(UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view)),
          UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view)));
    });
  }
}

class Box {
  final bindings.Box _bindings;

  Box([bindings.Box _bindings]) : _bindings = _bindings ?? bindings.Box();

  int get nonceBytes => _bindings.nonceBytes;

  int get seedBytes => _bindings.seedBytes;

  void _checkKeyPair(Uint8List publicKey, Uint8List secretKey) {
    checkExpectedLengthOf(publicKey.length, _bindings.publicKeyBytes, 'publicKey');
    checkExpectedLengthOf(secretKey.length, _bindings.secretKeyBytes, 'secretKey');
  }

  void _checkNonce(Uint8List nonce) {
    checkExpectedLengthOf(nonce.length, _bindings.nonceBytes, 'nonce');
  }

  /// Throws [ArgumentError] when arguments for the crypto_box_easy interface
  /// are false.
  void _checkEasyArguments(Uint8List nonce, Uint8List publicKey, Uint8List secretKey) {
    _checkNonce(nonce);
    _checkKeyPair(publicKey, secretKey);
  }

  /// Throws [ArgumentError] when arguments for the crypto_box_afternm interface are false
  void _checkAfterNumerousArguments(Uint8List nonce, Uint8List key) {
    _checkNonce(nonce);
    checkExpectedLengthOf(key.length, _bindings.beforeNumerousBytes, 'key');
  }

  /// Encrypts [message] with the recipient's [publicKey] and the senders [secretKey].
  /// {@macro dart_sodium_keypair_length}
  /// {@macro dart_sodium_nonce_length}
  Uint8List easy(Uint8List message, Uint8List nonce, Uint8List publicKey, Uint8List secretKey) {
    _checkEasyArguments(nonce, publicKey, secretKey);
    return free2freeZero2(
      nonce.asArray,
      Uint8Array.allocate(count: message.length + _bindings.macBytes)..view.setAll(0, message),
      publicKey.asArray,
      secretKey.asArray,
      (noncePtr, cPtr, pkPtr, skPtr) {
        final result =
            _bindings.easy(cPtr.rawPtr, cPtr.rawPtr, message.length, noncePtr.rawPtr, pkPtr.rawPtr, skPtr.rawPtr);
        if (result != 0) {
          throw Error();
        }
        return Uint8List.fromList(cPtr.view);
      },
    );
  }

  /// Opens [message] encrypted by [easy]. [nonce], [publicKey] and [secretKey] must be the same.
  Uint8List openEasy(Uint8List ciphertext, Uint8List nonce, Uint8List publicKey, Uint8List secretKey) {
    _checkEasyArguments(nonce, publicKey, secretKey);
    return free2freeZero2(
      nonce.asArray,
      ciphertext.asArray,
      publicKey.asArray,
      secretKey.asArray,
      (noncePtr, cPtr, pkPtr, skPtr) {
        final result = _bindings.openEasy(
            cPtr.rawPtr, cPtr.rawPtr, ciphertext.length, noncePtr.rawPtr, pkPtr.rawPtr, skPtr.rawPtr);
        if (result != 0) {
          throw Error();
        }
        return cPtr.view.sublist(0, ciphertext.length - _bindings.macBytes);
      },
    );
  }

  /// Generates a shared key to encrypt all onward messages. Can improve performance.
  /// {@macro dart_sodium_keypair_length}
  Uint8List beforeNumerous(Uint8List publicKey, Uint8List secretKey) {
    _checkKeyPair(publicKey, secretKey);
    return freeZero3(
      publicKey.asArray,
      secretKey.asArray,
      Uint8Array.allocate(count: _bindings.beforeNumerousBytes),
      (pkPtr, skPtr, sharedKeyPtr) {
        final result = _bindings.beforeNm(sharedKeyPtr.rawPtr, pkPtr.rawPtr, skPtr.rawPtr);
        if (result != 0) {
          throw Error();
        }
        return UnmodifiableUint8ListView(Uint8List.fromList(sharedKeyPtr.view));
      },
    );
  }

  /// Encrypts [message] with a shared key generated by [beforeNumerous].
  /// {@macro dart_sodium_nonce_length}
  Uint8List easyAfterNumerous(Uint8List message, Uint8List nonce, Uint8List key) {
    _checkAfterNumerousArguments(nonce, key);
    return free2freeZero1(
      nonce.asArray,
      Uint8Array.allocate(count: message.length + _bindings.macBytes)..view.setAll(0, message),
      key.asArray,
      (noncePtr, cPtr, keyPtr) {
        final result = _bindings.easyAfterNm(cPtr.rawPtr, cPtr.rawPtr, message.length, noncePtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw Error();
        }
        return Uint8List.fromList(cPtr.view);
      },
    );
  }

  /// Decrypts [ciphertext] generated by [easyAfterNumerous].
  /// [key] and [nonce] must be the same.
  Uint8List openEasyAfterNumerous(Uint8List ciphertext, Uint8List nonce, Uint8List key) {
    _checkAfterNumerousArguments(nonce, key);
    return free2freeZero1(
      nonce.asArray,
      ciphertext.asArray,
      key.asArray,
      (noncePtr, cPtr, keyPtr) {
        final result =
            _bindings.openEasyAfterNm(cPtr.rawPtr, cPtr.rawPtr, ciphertext.length, noncePtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw Error();
        }
        return cPtr.view.sublist(0, ciphertext.length - _bindings.macBytes);
      },
    );
  }
}
