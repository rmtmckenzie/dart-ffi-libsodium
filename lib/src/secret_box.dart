import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/secretbox.dart' as bindings;
import 'helpers/internal_helpers.dart';
import 'random_bytes.dart';
import 'shared.dart';

/// Authenticated encryption of single messages.
class SecretBox {
  final bindings.SecretBox _bindings;
  final RandomBytes _randomBytes;
  final UnmodifiableUint8ListView key;

  SecretBox._(this.key, this._bindings, this._randomBytes);

  int get nonceBytes => _bindings.nonceBytes;

  /// Instantiates with a newly generated key.
  factory SecretBox.generateKey([bindings.SecretBox secretBox, RandomBytes randomBytes]) {
    final _binding = secretBox ?? bindings.SecretBox();
    final _randomBytes = randomBytes ?? RandomBytes();

    final key = freeZero1(
      Uint8Array.allocate(count: _binding.keyBytes),
      (keyPtr) {
        _binding.keygen(keyPtr.rawPtr);
        return Uint8List.fromList(keyPtr.view);
      },
    );

    return SecretBox._(UnmodifiableUint8ListView(key), _binding, _randomBytes);
  }

  /// Instantiates with given key.
  /// [key] must be [SecretBox.keyBytes] long.
  factory SecretBox.fromKey(Uint8List key, [bindings.SecretBox secretBox, RandomBytes randomBytes]) {
    final _binding = secretBox ?? bindings.SecretBox();
    final _randomBytes = randomBytes ?? RandomBytes();
    checkExpectedLengthOf(key.length, _binding.keyBytes, 'key');
    return SecretBox._(UnmodifiableUint8ListView(key), _binding, _randomBytes);
  }

  /// Encrypts [message] with [key].
  /// If [nonce] is left empty, a nonce will be generated and stored in [SecretBox.nonce].
  /// Otherwise [nonce] must be [nonceBytes] long.
  EncryptResult encrypt(Uint8List message, {Uint8List nonce}) {
    if (nonce == null) {
      nonce = _randomBytes.buffer(_bindings.nonceBytes);
    } else {
      checkExpectedLengthOf(nonce.length, _bindings.nonceBytes, 'nonce');
    }

    return free3freeZero1(
      message.asArray,
      nonce.asArray,
      Uint8Array.allocate(count: message.length + _bindings.macBytes),
      key.asArray,
      (messagePtr, noncePtr, cipherTextPtr, keyPtr) {
        final result =
            _bindings.easy(cipherTextPtr.rawPtr, messagePtr.rawPtr, message.length, noncePtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw Exception();
        }
        return EncryptResult(cipher: Uint8List.fromList(cipherTextPtr.view), nonce: nonce);
      },
    );
  }

  /// Decrypts a message encrypted with [encrypt].
  Uint8List decrypt(Uint8List ciphertext, Uint8List nonce) {
    checkExpectedLengthOf(nonce.length, _bindings.nonceBytes, 'nonce');

    return free3freeZero1(
      ciphertext.asArray,
      nonce.asArray,
      Uint8Array.allocate(count: ciphertext.length - _bindings.macBytes),
      key.asArray,
      (cPtr, noncePtr, messagePtr, keyPtr) {
        final result =
            _bindings.openEasy(messagePtr.rawPtr, cPtr.rawPtr, ciphertext.length, noncePtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw Exception();
        }
        return Uint8List.fromList(messagePtr.view);
      },
    );
  }
}
