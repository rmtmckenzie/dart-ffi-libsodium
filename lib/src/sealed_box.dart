import 'dart:typed_data';

import 'package:dart_sodium/box.dart';
import 'package:dart_sodium/src/helpers/internal_helpers.dart';
import 'package:dart_sodium/src/helpers/memory_array.dart';
import 'package:meta/meta.dart';

import 'bindings/box.dart' as bindings;
import 'bindings/sealedbox.dart' as bindings;

class SealedBox {
  final bindings.SealedBox _bindings;
  final bindings.Box _box;

  SealedBox({bindings.SealedBox binding, bindings.Box box})
      : _bindings = binding ?? bindings.SealedBox(),
        _box = box ?? bindings.Box();

  int get seedBytes => _box.seedBytes;

  KeyPair generateKeyPair() {
    return KeyPair(_box);
  }

  KeyPair seedKeyPair(Uint8List seed) {
    return KeyPair.fromSeed(seed, _box);
  }

  Uint8List open(Uint8List cipher, KeyPair keyPair) {
    return free3freeZero1(
      Uint8Array.allocate(count: cipher.length - _bindings.sealBytes),
      cipher.asArray,
      keyPair.publicKey.asArray,
      keyPair.secretKey.asArray,
      (messagePtr, cipherPtr, publicKeyPtr, secretKeyPtr) {
        final result = _bindings.open(
            messagePtr.rawPtr, cipherPtr.rawPtr, cipherPtr.length, publicKeyPtr.rawPtr, secretKeyPtr.rawPtr);
        if (result != 0) {
          throw Exception('result: $result');
        }
        return UnmodifiableUint8ListView(Uint8List.fromList(messagePtr.view));
      },
    );
  }

  Uint8List seal(Uint8List message, {@required Uint8List publicKey}) {
    return free3(
      Uint8Array.allocate(count: message.length + _bindings.sealBytes),
      message.asArray,
      publicKey.asArray,
      (cipherPtr, messagePtr, publicKeyPtr) {
        final result = _bindings.seal(cipherPtr.rawPtr, messagePtr.rawPtr, messagePtr.length, publicKeyPtr.rawPtr);
        if (result != 0) {
          throw Exception();
        }
        return UnmodifiableUint8ListView(Uint8List.fromList(cipherPtr.view));
      },
    );
  }
}
