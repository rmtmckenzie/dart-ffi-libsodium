import 'dart:convert';

import './init.dart';
import 'package:test/test.dart';
import 'package:dart_sodium/secret_key_crypto.dart';

main() {
  test("authenticate message", () {
    init();
    Authenticator auth;
    try {
      final key = Authenticator.keyGen();
      auth = Authenticator(key);
      final msg = utf8.encode("my message");
      final authTag = auth.authenticate(msg);

      final isValid = auth.verify(msg, authTag);
      expect(isValid, true);
    } finally {
      auth.close();
    }
  });
}
