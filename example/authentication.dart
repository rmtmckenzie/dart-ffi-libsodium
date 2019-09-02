import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/auth.dart';

void main() {
  init("./libsodium");

  final key = Authenticator.keyGen();
  final msg = utf8.encode("message");
  final auth = Authenticator(key);
  try {
    final tag = auth.authenticate(msg);

    final isValid = auth.verify(msg, tag);
    assert(isValid == true);
  } finally {
    auth.close();
  }
}
