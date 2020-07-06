import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/key_exchange.dart' as bindings;
import 'internal_helpers.dart';

class KeyPairError extends Error {
  @override
  String toString() {
    return 'Failed to generate key pair';
  }
}

class SessionKeyError extends Error {
  @override
  String toString() {
    return 'Failed to generate session key';
  }
}

class KeyExchange {
  final bindings.KeyExchange _bindings;

  KeyExchange([bindings.KeyExchange _bindings]) : _bindings = _bindings ?? bindings.KeyExchange();

  int get publicKeyBytes => _bindings.publicKeyBytes;

  int get secretKeyBytes => _bindings.secretKeyBytes;

  int get sessionKeyBytes => _bindings.sessionKeyBytes;

  KeyPair generateKeyPair() {
    return free1freeZero1(
      Uint8Array.allocate(count: _bindings.publicKeyBytes),
      Uint8Array.allocate(count: _bindings.secretKeyBytes),
      (pkPtr, skPtr) {
        final result = _bindings.keyPair(pkPtr.rawPtr, skPtr.rawPtr);
        if (result != 0) {
          throw KeyPairError();
        }

        final sk = UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view));
        final pk = UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view));

        return KeyPair._(pk, sk);
      },
    );
  }

  KeyPair keyPairFromSeed(Uint8List seed) {
    checkExpectedLengthOf(seed.length, _bindings.seedBytes, 'seed');

    return free2freeZero1(
      seed.asArray,
      Uint8Array.allocate(count: _bindings.publicKeyBytes),
      Uint8Array.allocate(count: _bindings.secretKeyBytes),
      (seedPtr, pkPtr, skPtr) {
        final result = _bindings.seedKeyPair(pkPtr.rawPtr, skPtr.rawPtr, seedPtr.rawPtr);
        if (result != 0) {
          throw KeyPairError();
        }
        final sk = UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view));
        final pk = UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view));
        return KeyPair._(pk, sk);
      },
    );
  }

  UnmodifiableUint8ListView generateSessionKey(Uint8List clientPublicKey, Uint8List clientSecretKey, Uint8List serverPublicKey) {
    assert(clientPublicKey.length == _bindings.publicKeyBytes);
    assert(serverPublicKey.length == _bindings.publicKeyBytes);
    assert(clientSecretKey.length == _bindings.secretKeyBytes);
    final cskPtr = clientSecretKey.asArray;
    final cpkPtr = clientPublicKey.asArray;
    final spkPtr = serverPublicKey.asArray;
    final keyPtr = Uint8Array.allocate(count: _bindings.sessionKeyBytes);
    final result = _bindings.clientSessionKeys(keyPtr.rawPtr, nullptr.cast(), cpkPtr.rawPtr, cskPtr.rawPtr, spkPtr.rawPtr);

    final key = UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
    keyPtr.freeZero();
    cskPtr.freeZero();
    cpkPtr.free();
    spkPtr.free();

    if (result != 0) {
      throw SessionKeyError();
    }
    return key;
  }

  ClientSessionKeys generateClientSessionKeys(Uint8List clientPublicKey, Uint8List clientSecretKey, Uint8List serverPublicKey) {
    checkExpectedLengthOf(clientPublicKey.length, _bindings.publicKeyBytes, 'client public key');
    checkExpectedLengthOf(serverPublicKey.length, _bindings.publicKeyBytes, 'server public key');
    checkExpectedLengthOf(clientSecretKey.length, _bindings.secretKeyBytes, 'client secret key');

    return free2freeZero3(
      serverPublicKey.asArray,
      clientPublicKey.asArray,
      clientSecretKey.asArray,
      Uint8Array.allocate(count: _bindings.sessionKeyBytes), // rkPtr
      Uint8Array.allocate(count: _bindings.sessionKeyBytes), // tkPtr
      (spkPtr, cpkPtr, cskPtr, rkPtr, tkPtr) {
        final result = _bindings.clientSessionKeys(rkPtr.rawPtr, tkPtr.rawPtr, cpkPtr.rawPtr, cskPtr.rawPtr, spkPtr.rawPtr);
        if (result != 0) {
          throw KeyPairError();
        }

        final rk = UnmodifiableUint8ListView(Uint8List.fromList(rkPtr.view));
        final tk = UnmodifiableUint8ListView(Uint8List.fromList(tkPtr.view));

        return ClientSessionKeys._(rk, tk);
      },
    );
  }

  ServerSessionKeys generateServerSessionKeys(Uint8List serverPublicKey, Uint8List serverSecretKey, Uint8List clientPublicKey) {
    checkExpectedLengthOf(clientPublicKey.length, _bindings.publicKeyBytes, 'client public key');
    checkExpectedLengthOf(serverPublicKey.length, _bindings.publicKeyBytes, 'server public key');
    checkExpectedLengthOf(serverSecretKey.length, _bindings.secretKeyBytes, 'server secret key');

    return free2freeZero3(
      clientPublicKey.asArray,
      serverPublicKey.asArray,
      serverSecretKey.asArray,
      Uint8Array.allocate(count: _bindings.sessionKeyBytes), // rkPtr
      Uint8Array.allocate(count: _bindings.sessionKeyBytes), // tkPtr
      (cpkPtr, spkPtr, sskPtr, rkPtr, tkPtr) {
        final result = _bindings.serverSessionKeys(rkPtr.rawPtr, tkPtr.rawPtr, spkPtr.rawPtr, sskPtr.rawPtr, cpkPtr.rawPtr);
        if (result != 0) {
          throw KeyPairError();
        }

        final rk = UnmodifiableUint8ListView(Uint8List.fromList(rkPtr.view));
        final tk = UnmodifiableUint8ListView(Uint8List.fromList(tkPtr.view));

        return ServerSessionKeys._(rk, tk);
      },
    );
  }
}

class KeyPair {
  final UnmodifiableUint8ListView secretKey, publicKey;

  const KeyPair._(this.publicKey, this.secretKey);
}

abstract class SessionKeys {
  final UnmodifiableUint8ListView receiverKey, toReceiverKey;

  SessionKeys._(this.receiverKey, this.toReceiverKey);
}

class ClientSessionKeys extends SessionKeys {
  ClientSessionKeys._(Uint8List receiverKey, Uint8List toReceiverKey) : super._(receiverKey, toReceiverKey);
}

class ServerSessionKeys extends SessionKeys {
  ServerSessionKeys._(Uint8List receiverKey, Uint8List toReceiverKey) : super._(receiverKey, toReceiverKey);
}
