import 'package:dart_sodium/key_exchange.dart';
import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final kx = KeyExchange();
  final randomBytes = RandomBytes();

  test('generate key pair', () {
    final keyPair = kx.generateKeyPair();
    expect(keyPair.publicKey.length, kx.publicKeyBytes);
    expect(keyPair.secretKey.length, kx.secretKeyBytes);
  });

  test('generate key pair from seed', () {
    final seed = randomBytes.buffer(kx.secretKeyBytes);
    final keyPair = kx.keyPairFromSeed(seed);
    final keyPair2 = kx.keyPairFromSeed(seed);
    expect(keyPair.secretKey, keyPair2.secretKey);
    expect(keyPair.publicKey, keyPair2.publicKey);
  });

  test('generate client session keys', () {
    final keyPair = kx.generateKeyPair();
    final serverPublicKey = randomBytes.buffer(kx.publicKeyBytes);
    final sessionKeys = kx.generateClientSessionKeys(keyPair.publicKey, keyPair.secretKey, serverPublicKey);
    expect(sessionKeys.receiverKey.length, kx.sessionKeyBytes);
    expect(sessionKeys.toReceiverKey.length, kx.sessionKeyBytes);
  });
  test('generate server session keys', () {
    final keyPair = kx.generateKeyPair();
    final clientPublicKey = randomBytes.buffer(kx.publicKeyBytes);
    final sessionKeys = kx.generateServerSessionKeys(keyPair.publicKey, keyPair.secretKey, clientPublicKey);
    expect(sessionKeys.receiverKey.length, kx.sessionKeyBytes);
    expect(sessionKeys.toReceiverKey.length, kx.sessionKeyBytes);
  });
}
