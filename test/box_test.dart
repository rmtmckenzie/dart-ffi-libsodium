import 'dart:convert';

import 'package:dart_sodium/box.dart';
import 'package:dart_sodium/random.dart';
import 'package:test/test.dart';

import 'init.dart';

main() {
  test("encrypt and decrypt a message", () {
    init();
    final keys = Box.keyPair();
    final box = Box(keys.publicKey, keys.secretKey);
    final msg = utf8.encode("hello world");
    final nonce = buffer(Box.nonceBytes);
    try {
      final ciphertext = box.easy(msg, nonce);
      final decrypted = box.openEasy(ciphertext, nonce);
      expect(msg, decrypted);
    } finally {
      box.close();
    }
  });
}
