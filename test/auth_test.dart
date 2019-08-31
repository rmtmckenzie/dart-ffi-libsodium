import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:test/test.dart';
import 'package:dart_sodium/auth.dart';

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
