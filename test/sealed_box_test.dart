import 'dart:convert';

import 'package:dart_sodium/box.dart';
import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/sealed_box.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final sealedBox = SealedBox();
  final box = Box();
  final randomBytes = RandomBytes();

  test('encrypt and decrypt individual message', () {
    final message = utf8.encode('hello world');

    final keyPair = sealedBox.generateKeyPair();

    final encrypted = sealedBox.seal(message, publicKey: keyPair.publicKey);
    final decrypted = sealedBox.open(encrypted, keyPair);

    expect(message, decrypted);
  });

  test('seeded key identical', () {
    final seed = randomBytes.buffer(box.seedBytes);
    final keyPair1 = sealedBox.seedKeyPair(seed);
    final keyPair2 = sealedBox.seedKeyPair(seed);

    expect(keyPair1.secretKey, keyPair2.secretKey);
    expect(keyPair1.publicKey, keyPair2.publicKey);
  });

  test('encrypt and decrypt with seeded key', () {
    final message = utf8.encode('goodbye world');

    final seed = randomBytes.buffer(box.seedBytes);
    final keyPair1 = sealedBox.seedKeyPair(seed);
    final keyPair2 = sealedBox.seedKeyPair(seed);

    final encrypted = sealedBox.seal(message, publicKey: keyPair1.publicKey);
    final decrypted = sealedBox.open(encrypted, keyPair2);

    expect(message, decrypted);
  });
}
