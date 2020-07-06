import 'dart:convert';

import 'package:dart_sodium/key_derivation.dart';
import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final kdf = KeyDerivation();
  final randomBytes = RandomBytes();

  test('derive key', () {
    final key = kdf.keyGen();
    final context = utf8.encode('userdata');
    final derivedKey = kdf.deriveFromKey(32, 0, context, key);
    expect(derivedKey.length, 32);
  });

  test('nonce extension', () {
    final key = randomBytes.buffer(32);
    final nonce = randomBytes.buffer(16);
    final subkey = kdf.hchacha20(nonce, key);
    expect(subkey.length, 32);
  });

  test('nonce extension with constant', () {
    final key = randomBytes.buffer(32);
    final nonce = randomBytes.buffer(16);
    final constant = randomBytes.buffer(16);
    final subkey = kdf.hchacha20(nonce, key, constant);
    expect(subkey.length, 32);
  });
}
