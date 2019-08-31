import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/secretbox.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:dart_sodium/helpers.dart';
import 'package:test/test.dart';

main() {
  test("encrypt and decrypt easy", () {
    init();
    SecretBox box;
    try {
      final key = SecretBox.keyGen();
      box = SecretBox(key);
      final msg = utf8.encode("my message");
      final nonce = rand.buffer(SecretBox.nonceBytes);
      final ciphertext = box.easy(msg, nonce);
      final cleartext = box.openEasy(ciphertext, nonce);
      expect(memoryCompare(msg, cleartext), true);
    } finally {
      box.close();
    }
  });
}
