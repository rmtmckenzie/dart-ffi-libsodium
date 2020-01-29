import 'dart:convert';

import 'package:test/test.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/key_derivation.dart' as kdf;
import 'package:dart_sodium/random_bytes.dart' as random_bytes;

void main() {
  sodium.init();
  test('derive key', () {
    final key = kdf.keyGen();
    final context = utf8.encode('userdata');
    final derivedKey = kdf.deriveFromKey(32, 0, context, key);
    expect(derivedKey.length, 32);
  });

  test('nonce extension', () {
    final key = random_bytes.buffer(32);
    final nonce = random_bytes.buffer(16);
    final subkey = kdf.hchacha20(nonce, key);
    expect(subkey.length, 32);
  });

  test('nonce extension with constant', () {
    final key = random_bytes.buffer(32);
    final nonce = random_bytes.buffer(16);
    final constant = random_bytes.buffer(16);
    final subkey = kdf.hchacha20(nonce, key, constant);
    expect(subkey.length, 32);
  });
}
