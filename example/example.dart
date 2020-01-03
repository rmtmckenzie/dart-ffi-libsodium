import 'dart:convert';

import 'package:dart_sodium/secret_box.dart' as secret_box;
import 'package:dart_sodium/random_bytes.dart' as random_bytes;
import 'package:dart_sodium/sodium.dart' as sodium;

void main(List<String> args) {
  sodium.init();
  final key = secret_box.keyGen();
  final msg = utf8.encode('hello world');

  final nonce = random_bytes.buffer(secret_box.nonceBytes);
  final c = secret_box.easy(msg, nonce, key);

  final decrypted = secret_box.openEasy(c, nonce, key);
}
