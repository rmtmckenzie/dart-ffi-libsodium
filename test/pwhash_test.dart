import 'dart:convert';

import 'package:dart_sodium/pwhash.dart' as pwhash;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('Hash and verify password', () {
    final password = utf8.encode('my password');
    final hash = pwhash.store(
        password, pwhash.OpsLimit.interactive, pwhash.MemLimit.interactive);
    final isValid = pwhash.verify(hash, password);

    expect(isValid, true);
  });
}
