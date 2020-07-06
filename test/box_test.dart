import 'dart:convert';

import 'package:dart_sodium/box.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:dart_sodium/random_bytes.dart';
import 'package:test/test.dart';

void main() {

  LibSodium.init();
  final box = Box();
  final randomBytes = RandomBytes();

  test('Encrypt and decrypt a message', () {

    final keyPair = KeyPair();
    final message = utf8.encode('hello world');
    final nonce = randomBytes.buffer(box.nonceBytes);

    final encrypted =
        box.easy(message, nonce, keyPair.publicKey, keyPair.secretKey);
    final decrypted =
        box.openEasy(encrypted, nonce, keyPair.publicKey, keyPair.secretKey);

    expect(decrypted, message);
  });

  test('Encrypt and decrypt a message with precalculated key', () {
    final keyPair = KeyPair();
    final key = box.beforeNumerous(keyPair.publicKey, keyPair.secretKey);
    final message = utf8.encode('hello world');
    final nonce = randomBytes.buffer(box.nonceBytes);

    final encrypted = box.easyAfterNumerous(message, nonce, key);
    final decrypted = box.openEasyAfterNumerous(encrypted, nonce, key);

    expect(decrypted, message);
  });

}
