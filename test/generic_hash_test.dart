import 'dart:convert';

import 'package:dart_sodium/generic_hash.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final hash = GenericHash();

  test('Hash a message with key', () {
    final key = hash.keyGen();
    final message = utf8.encode('hello world');
    final hashed = hash.genericHash(message, key: key);
    final hashed2 = hash.genericHash(message, key: key);

    expect(hashed, hashed2);
  });

  test('Hash a message without key', () {
    final message = utf8.encode('hello world');
    final hashed = hash.genericHash(message);
    final hashed2 = hash.genericHash(message);
    expect(hashed, hashed2);
  });

  test('Hash multi part message with key', () {
    final key = hash.keyGen();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');
    final hashStream = hash.stream(key: key);
    hashStream.update(message);
    hashStream.update(message2);
    final hashed = hashStream.finalize();

    final hashStream2 = hash.stream(key: key);
    hashStream2.update(message);
    hashStream2.update(message2);
    final hashed2 = hashStream.finalize();

    expect(hashed, hashed2);
  });

  test('Hash multi part message without key', () {
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');
    final hashStream = hash.stream();
    hashStream.update(message);
    hashStream.update(message2);
    final hashed = hashStream.finalize();

    final hashStream2 = hash.stream();
    hashStream2.update(message);
    hashStream2.update(message2);
    final hashed2 = hashStream.finalize();
    expect(hashed, hashed2);
  });
}
