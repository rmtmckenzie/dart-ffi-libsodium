import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init();

  final key = Auth.keyGen();
  final msg = RandomBytes.buf(16);
  final tag = Auth.auth(msg, key);

  final isValid = Auth.verify(tag, msg, key);
}
