import 'dart:convert';

import 'package:dart_sodium/secret_box.dart' as secret_box;
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('encrypt and decrypt individual message', () {
    final key = secret_box.keyGen();
    final message = utf8.encode('hello world');
    final nonce = rand_bytes.buffer(secret_box.nonceBytes);

    final encrypted = secret_box.easy(message, nonce, key);
    final decrypted = secret_box.openEasy(encrypted, nonce, key);

    expect(message, decrypted);
  });
}
