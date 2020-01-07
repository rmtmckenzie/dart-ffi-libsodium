import 'dart:convert';

import 'package:dart_sodium/auth.dart' as auth;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('Authenticate and verify a message', () {
    final key = auth.keyGen();
    final message = utf8.encode('hello world');
    final authTag = auth.auth(message, key);

    final isValid = auth.verify(authTag, message, key);

    expect(isValid, true);
  });
}
