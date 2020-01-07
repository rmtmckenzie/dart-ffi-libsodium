import 'dart:convert';

import 'package:dart_sodium/box.dart' as box;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('Encrypt and decrypt a message', () {
    final keyPair = box.KeyPair.generate();
    final message = utf8.encode('hello world');
    final nonce = rand_bytes.buffer(box.nonceBytes);

    final encrypted =
        box.easy(message, nonce, keyPair.publicKey, keyPair.secretKey);
    final decrypted =
        box.openEasy(encrypted, nonce, keyPair.publicKey, keyPair.secretKey);

    expect(decrypted, message);
  });

  test('Encrypt and decrypt a message with precalculated key', () {
    final keyPair = box.KeyPair.generate();
    final key = box.beforeNumerous(keyPair.publicKey, keyPair.secretKey);
    final message = utf8.encode('hello world');
    final nonce = rand_bytes.buffer(box.nonceBytes);

    final encrypted = box.easyAfterNumerous(message, nonce, key);
    final decrypted = box.openEasyAfterNumerous(encrypted, nonce, key);

    expect(decrypted, message);
  });
}
