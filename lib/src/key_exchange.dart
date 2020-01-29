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

class KeyPair {
  final UnmodifiableUint8ListView secretKey, publicKey;

  const KeyPair._(this.publicKey, this.secretKey);
  factory KeyPair.generate() {
    final skPtr = Uint8Array.allocate(count: bindings.secretKeyBytes);
    final pkPtr = Uint8Array.allocate(count: bindings.publicKeyBytes);
    final result = bindings.keyPair(pkPtr.rawPtr, skPtr.rawPtr);
    final sk = UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view));
    final pk = UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view));
    skPtr.freeZero();
    pkPtr.free();
    if (result != 0) {
      throw KeyPairError();
    }
    return KeyPair._(pk, sk);
  }

  factory KeyPair.fromSeed(Uint8List seed) {
    assert(seed.length == bindings.seedBytes);
    final skPtr = Uint8Array.allocate(count: bindings.secretKeyBytes);
    final pkPtr = Uint8Array.allocate(count: bindings.publicKeyBytes);
    final seedPtr = Uint8Array.fromTypedList(seed);
    final result =
        bindings.seedKeyPair(pkPtr.rawPtr, skPtr.rawPtr, seedPtr.rawPtr);
    final sk = UnmodifiableUint8ListView(Uint8List.fromList(skPtr.view));
    final pk = UnmodifiableUint8ListView(Uint8List.fromList(pkPtr.view));
    skPtr.freeZero();
    pkPtr.free();
    if (result != 0) {
      throw KeyPairError();
    }
    return KeyPair._(pk, sk);
  }
}

abstract class SessionKeys {
  final UnmodifiableUint8ListView receiverKey, toReceiverKey;

  SessionKeys._(this.receiverKey, this.toReceiverKey);
}

class ClientSessionKeys extends SessionKeys {
  static UnmodifiableUint8ListView generateSessionKey(Uint8List clientPublicKey,
      Uint8List clientSecretKey, Uint8List serverPublicKey) {
    assert(clientPublicKey.length == bindings.publicKeyBytes);
    assert(serverPublicKey.length == bindings.publicKeyBytes);
    assert(clientSecretKey.length == bindings.secretKeyBytes);
    final cskPtr = Uint8Array.fromTypedList(clientSecretKey);
    final cpkPtr = Uint8Array.fromTypedList(clientPublicKey);
    final spkPtr = Uint8Array.fromTypedList(serverPublicKey);
    final keyPtr = Uint8Array.allocate(count: bindings.sessionKeyBytes);
    final result = bindings.clientSessionKeys(keyPtr.rawPtr, nullptr.cast(),
        cpkPtr.rawPtr, cskPtr.rawPtr, spkPtr.rawPtr);

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

  ClientSessionKeys._(Uint8List receiverKey, Uint8List toReceiverKey)
      : super._(receiverKey, toReceiverKey);

  factory ClientSessionKeys.generate(Uint8List clientPublicKey,
      Uint8List clientSecretKey, Uint8List serverPublicKey) {
    assert(clientPublicKey.length == bindings.publicKeyBytes);
    assert(serverPublicKey.length == bindings.publicKeyBytes);
    assert(clientSecretKey.length == bindings.secretKeyBytes);
    final cskPtr = Uint8Array.fromTypedList(clientSecretKey);
    final cpkPtr = Uint8Array.fromTypedList(clientPublicKey);
    final spkPtr = Uint8Array.fromTypedList(serverPublicKey);
    final rkPtr = Uint8Array.allocate(count: bindings.sessionKeyBytes);
    final tkPtr = Uint8Array.allocate(count: bindings.sessionKeyBytes);
    final result = bindings.clientSessionKeys(rkPtr.rawPtr, tkPtr.rawPtr,
        cpkPtr.rawPtr, cskPtr.rawPtr, spkPtr.rawPtr);

    final rk = UnmodifiableUint8ListView(Uint8List.fromList(rkPtr.view));
    rkPtr.freeZero();
    final tk = UnmodifiableUint8ListView(Uint8List.fromList(tkPtr.view));
    tkPtr.freeZero();
    cskPtr.freeZero();
    cpkPtr.free();
    spkPtr.free();

    if (result != 0) {
      throw KeyPairError();
    }
    return ClientSessionKeys._(rk, tk);
  }
}

class ServerSessionKeys extends SessionKeys {
  ServerSessionKeys._(Uint8List receiverKey, Uint8List toReceiverKey)
      : super._(receiverKey, toReceiverKey);

  factory ServerSessionKeys.generate(Uint8List serverPublicKey,
      Uint8List serverSecretKey, Uint8List clientPublicKey) {
    assert(clientPublicKey.length == bindings.publicKeyBytes);
    assert(serverPublicKey.length == bindings.publicKeyBytes);
    assert(serverSecretKey.length == bindings.secretKeyBytes);
    final sskPtr = Uint8Array.fromTypedList(serverSecretKey);
    final spkPtr = Uint8Array.fromTypedList(serverPublicKey);
    final cpkPtr = Uint8Array.fromTypedList(clientPublicKey);
    final rkPtr = Uint8Array.allocate(count: bindings.sessionKeyBytes);
    final tkPtr = Uint8Array.allocate(count: bindings.sessionKeyBytes);
    final result = bindings.serverSessionKeys(rkPtr.rawPtr, tkPtr.rawPtr,
        spkPtr.rawPtr, sskPtr.rawPtr, cpkPtr.rawPtr);

    final rk = UnmodifiableUint8ListView(Uint8List.fromList(rkPtr.view));
    rkPtr.freeZero();
    final tk = UnmodifiableUint8ListView(Uint8List.fromList(tkPtr.view));
    tkPtr.freeZero();
    sskPtr.freeZero();
    cpkPtr.free();
    spkPtr.free();

    if (result != 0) {
      throw KeyPairError();
    }
    return ServerSessionKeys._(rk, tk);
  }
}
