import 'dart:convert';

import 'package:dart_sodium/secret_box.dart';
import 'package:dart_sodium/sodium.dart';

void main(List<String> args) {
  LibSodium.init();
  final box = SecretBox.generateKey();
  final msg = utf8.encode('hello world');

  final encryptResult = box.encrypt(msg);

  final decrypted = box.decrypt(encryptResult.cipher, encryptResult.nonce);
  print(utf8.decode(decrypted));
}
