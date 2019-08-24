import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init();

  final key = SecretBox.keyGen();
  final plaintext = ascii.encode("my plaintext");
  final nonce = RandomBytes.buf(SecretBox.nonceBytes);
  final ciphertext = SecretBox.easy(plaintext, nonce, key);

  final decrypted = SecretBox.openEasy(ciphertext, nonce, key);
}
