import 'dart:convert';

import './init.dart';
import 'package:dart_sodium/password_hasing.dart';
import 'package:test/test.dart';

main() {
  test('store and verify', () {
    init();
    final pwd = utf8.encode("my password");
    final hash = store(pwd, OpsLimit.min, MemLimit.min);
    final isValid = storeVerify(hash, pwd);
    expect(isValid, true);
  });
}
