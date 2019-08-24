import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:dart_sodium/secretbox.dart' as box;

void main() {
  init();

  final key = box.keyGen();
  final plaintext = ascii.encode("my plaintext");
  final nonce = rand.buf(box.nonceBytes);
  final ciphertext = box.easy(plaintext, nonce, key);

  final decrypted = box.openEasy(ciphertext, nonce, key);
}
