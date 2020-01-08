import 'dart:convert';

import 'package:dart_sodium/generic_hash.dart' as hash;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('Hash a message with key', () {
    final key = hash.keyGen();
    expect(key.length, hash.genericHashBytes);
    final message = utf8.encode('hello world');
    final hashed = hash.genericHash(message, key: key);
    expect(hashed.length, hash.genericHashBytes);
  });

  test('Hash a message without key', () {
    final message = utf8.encode('hello world');
    final hashed = hash.genericHash(message);
    expect(hashed.length, hash.genericHashBytes);
  });

  test('Hash multi part message with key', () {
    final key = hash.keyGen();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');
    final state = hash.init(key: key);
    hash.update(state, message);
    hash.update(state, message2);
    final hashed = hash.finish(state);
    expect(hashed.length, hash.genericHashBytes);
  });
}
