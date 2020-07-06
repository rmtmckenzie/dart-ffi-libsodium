import 'dart:convert';

import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/secret_box.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final randomBytes = RandomBytes();

  test('encrypt and decrypt individual message', () {
    final box = SecretBox.generateKey();
    final message = utf8.encode('hello world');
    final nonce = randomBytes.buffer(box.nonceBytes);

    final encrypted = box.encrypt(message, nonce: nonce);
    final decrypted = box.decrypt(encrypted.cipher, nonce);

    expect(message, decrypted);
  });

  test('encrypt and decrypt individual message w/ autogen nonce', () {
    final box = SecretBox.generateKey();
    final message = utf8.encode('goodbye world');

    final encrypted = box.encrypt(message);
    final decrypted = box.decrypt(encrypted.cipher, encrypted.nonce);

    expect(message, decrypted);
  });

  test('encrypt and decrypt w/ passed in key', () {
    final box1 = SecretBox.generateKey();
    final box2 = SecretBox.fromKey(box1.key);
    final message = utf8.encode('what\'s up world');

    final encrypted = box1.encrypt(message);
    final decrypted = box2.decrypt(encrypted.cipher, encrypted.nonce);

    expect(message, decrypted);
  });

  test('encrypt w/ passed in key and decrypt', () {
    final box2 = SecretBox.generateKey();
    final box1 = SecretBox.fromKey(box2.key);
    final message = utf8.encode('here we go again');

    final encrypted = box1.encrypt(message);
    final decrypted = box2.decrypt(encrypted.cipher, encrypted.nonce);

    expect(message, decrypted);
  });
}
