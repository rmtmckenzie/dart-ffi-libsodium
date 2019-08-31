import 'dart:convert';

import 'package:dart_sodium/secretbox.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:test/test.dart';

main() {
  test("encrypt and decrypt easy", () {
    SecretBox box;
    try {
      final key = SecretBox.keyGen();
      box = SecretBox(key);
      final msg = utf8.encode("my message");
      final nonce = rand.buffer(16);
      final ciphertext = box.easy(msg, nonce);

      final cleartext = box.openEasy(ciphertext, nonce);
      expect(msg, cleartext);
    } finally {
      box.close();
    }
  });
}
