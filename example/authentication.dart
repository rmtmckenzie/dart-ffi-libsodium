import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:dart_sodium/auth.dart' as auth;

void main() {
  init();

  final key = auth.keyGen();
  final msg = rand.buf(16);
  final tag = auth.auth(msg, key);

  final isValid = auth.verify(tag, msg, key);
}
