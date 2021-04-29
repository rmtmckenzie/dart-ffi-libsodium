import 'dart:ffi';
import 'dart:typed_data';

import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/src/helpers/internal_helpers.dart';
import 'package:dart_sodium/src/shared.dart';
import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/aead.dart' as bindings;

class AeadXChacha20Poly1305IETF {
  final bindings.AeadXChacha20Poly1305IETF _bindings;
  final UnmodifiableUint8ListView key;
  final RandomBytes _randomBytes;

  AeadXChacha20Poly1305IETF._(this.key, this._bindings, this._randomBytes);

  int get nonceBytes => _bindings.nonceBytes;

  int get aBytes => _bindings.aBytes;

  factory AeadXChacha20Poly1305IETF.generateKey([bindings.AeadXChacha20Poly1305IETF binding, RandomBytes randomBytes]) {
    final _binding = binding ?? bindings.AeadXChacha20Poly1305IETF();
    final _randomBytes = randomBytes ?? RandomBytes();

    final key = freeZero1(
      Uint8Array.allocate(count: _binding.keyBytes),
      (keyPtr) {
        _binding.keyGen(keyPtr.rawPtr);
        return Uint8List.fromList(keyPtr.view);
      },
    );

    return AeadXChacha20Poly1305IETF._(UnmodifiableUint8ListView(key), _binding, _randomBytes);
  }

  factory AeadXChacha20Poly1305IETF.fromKey(Uint8List key,
      [bindings.AeadXChacha20Poly1305IETF secretBox, RandomBytes randomBytes]) {
    final _binding = secretBox ?? bindings.AeadXChacha20Poly1305IETF();
    final _randomBytes = randomBytes ?? RandomBytes();
    checkExpectedLengthOf(key.length, _binding.keyBytes, 'key');
    return AeadXChacha20Poly1305IETF._(UnmodifiableUint8ListView(key), _binding, _randomBytes);
  }

  EncryptResult encrypt(Uint8List message, {Uint8List nonce, Uint8List additionalData}) {
    if (nonce == null) {
      nonce = _randomBytes.buffer(_bindings.nonceBytes);
    } else {
      checkExpectedLengthOf(nonce.length, _bindings.nonceBytes, 'nonce');
    }

    return free5freeZero1(
      Uint8Array.allocate(count: message.length + _bindings.aBytes),
      Uint64Array.allocate(),
      message.asArray,
      additionalData?.asArray,
      nonce.asArray,
      key.asArray,
      (cipherPtr, cipherLengthPtr, messagePtr, additionalDataPtr, noncePtr, keyPtr) {
        final result = _bindings.encrypt(
          cipherPtr.rawPtr,
          cipherLengthPtr.rawPtr,
          messagePtr.rawPtr,
          messagePtr.length,
          additionalDataPtr.rawPtr,
          additionalDataPtr.length,
          nullptr,
          noncePtr.rawPtr,
          keyPtr.rawPtr,
        );
        if (result != 0) {
          throw Exception();
        }
        return EncryptResult(
            cipher: Uint8List.fromList(cipherPtr.view.sublist(0, cipherLengthPtr.view.first)), nonce: nonce);
      },
    );
  }

  Uint8List decrypt(Uint8List cipher, Uint8List nonce, {Uint8List additionalData}) {
    checkExpectedLengthOf(nonce.length, _bindings.nonceBytes, 'nonce');

    return free5freeZero1(
      Uint8Array.allocate(count: cipher.length - _bindings.aBytes),
      Uint64Array.allocate(),
      cipher.asArray,
      additionalData?.asArray,
      nonce.asArray,
      key.asArray,
      (messagePtr, messageLengthPtr, cipherPtr, additionalDataPtr, noncePtr, keyPtr) {
        final result = _bindings.decrypt(
          messagePtr.rawPtr,
          messageLengthPtr.rawPtr,
          nullptr,
          // nsec
          cipherPtr.rawPtr,
          cipherPtr.length,
          additionalDataPtr.rawPtr,
          additionalDataPtr.length,
          noncePtr.rawPtr,
          keyPtr.rawPtr,
        );
        if (result != 0) {
          throw Exception();
        }
        return Uint8List.fromList(messagePtr.view.sublist(0, messageLengthPtr.view.first));
      },
    );
  }
}
