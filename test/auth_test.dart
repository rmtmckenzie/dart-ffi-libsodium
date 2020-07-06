import 'dart:convert';

import 'package:dart_sodium/auth.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  test('Authenticate and verify a message', () {
    final auth = Authenticator.withNewKey();

    final message = utf8.encode('hello world');
    final authTag = auth.authenticate(message);

    final isValid = auth.verify(authTag, message);

    expect(isValid, true);
  });

  test('Encrypt and decrypt individual message w/ autogen nonce', () {
    final auth = Authenticator.withNewKey();
  });

  test('Encrypt and decrypt individual message w/ autogen nonce', () {
    final auth = Authenticator.withNewKey();
  });
}
