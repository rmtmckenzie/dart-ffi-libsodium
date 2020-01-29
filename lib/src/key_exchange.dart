import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/key_exchange.dart' as bindings;
import 'internal_helpers.dart';

class KeyPairException implements Exception {
  @override
  String toString() {
    return 'Failed to generate key pair';
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
      throw KeyPairException();
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
      throw KeyPairException();
    }
    return KeyPair._(pk, sk);
  }
}

abstract class SessionKeys {
  final UnmodifiableUint8ListView receiverKey, toReceiverKey;

  SessionKeys._(this.receiverKey, this.toReceiverKey);
}

class ClientSessionKeys extends SessionKeys {
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
      throw KeyPairException();
    }
    return ClientSessionKeys._(rk, tk);
  }
}
