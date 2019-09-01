import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:dart_sodium/secretbox.dart';

void main() {
  init("./libsodium");

  final plaintext = utf8.encode("my plaintext");
  final nonce = rand.buffer(SecretBox.nonceBytes);
  final key = SecretBox.keyGen();
  final box = SecretBox(key);
  try {
    final ciphertext = box.easy(plaintext, nonce);

    final decrypted = box.openEasy(ciphertext, nonce);
    assert(decrypted == plaintext);
  } finally {
    box.close();
  }
}
