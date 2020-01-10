import 'dart:convert';

import 'package:dart_sodium/generic_hash.dart' as hash;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
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
    final state = hash.init(key: key);
    hash.update(state, message);
    hash.update(state, message2);
    final hashed = hash.finish(state);

    final state2 = hash.init(key: key);
    hash.update(state2, message);
    hash.update(state2, message2);
    final hashed2 = hash.finish(state2);

    expect(hashed, hashed2);
  });

  test('Hash multi part message without key', () {
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');
    final state = hash.init();
    hash.update(state, message);
    hash.update(state, message2);
    final hashed = hash.finish(state);

    final state2 = hash.init();
    hash.update(state2, message);
    hash.update(state2, message2);
    final hashed2 = hash.finish(state2);
    expect(hashed, hashed2);
  });
}
