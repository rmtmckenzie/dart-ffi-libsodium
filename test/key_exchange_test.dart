import 'dart:convert';

import 'package:test/test.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/key_exchange.dart' as kx;
import 'package:dart_sodium/random_bytes.dart' as random_bytes;

void main() {
  sodium.init();
  test('generate key pair', () {
    final keyPair = kx.KeyPair.generate();
    expect(keyPair.publicKey.length, kx.publicKeyBytes);
    expect(keyPair.secretKey.length, kx.secretKeyBytes);
  });

  test('generate key pair from seed', () {
    final seed = random_bytes.buffer(kx.secretKeyBytes);
    final keyPair = kx.KeyPair.fromSeed(seed);
    final keyPair2 = kx.KeyPair.fromSeed(seed);
    expect(keyPair.secretKey, keyPair2.secretKey);
    expect(keyPair.publicKey, keyPair2.publicKey);
  });

  test('generate client session keys', () {
    final keyPair = kx.KeyPair.generate();
    final serverPublicKey = random_bytes.buffer(kx.publicKeyBytes);
    final sessionKeys = kx.ClientSessionKeys.generate(
        keyPair.publicKey, keyPair.secretKey, serverPublicKey);
    expect(sessionKeys.receiverKey.length, kx.sessionKeyBytes);
    expect(sessionKeys.toReceiverKey.length, kx.sessionKeyBytes);
  });
  test('generate server session keys', () {
    final keyPair = kx.KeyPair.generate();
    final clientPublicKey = random_bytes.buffer(kx.publicKeyBytes);
    final sessionKeys = kx.ServerSessionKeys.generate(
        keyPair.publicKey, keyPair.secretKey, clientPublicKey);
    expect(sessionKeys.receiverKey.length, kx.sessionKeyBytes);
    expect(sessionKeys.toReceiverKey.length, kx.sessionKeyBytes);
  });
}
