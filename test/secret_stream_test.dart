import 'dart:convert';

import 'package:dart_sodium/secret_stream.dart' as secret_stream;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  test('encrypt and decrypt message as stream', () {
    sodium.init();
    final key = secret_stream.keyGen();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');

    final initPush = secret_stream.initPush(key);
    final encChunk = secret_stream.push(initPush.state, message);
    final encChunk2 = secret_stream.push(initPush.state, message2);

    final pullState = secret_stream.initPull(initPush.header, key);
    final decChunk = secret_stream.pull(pullState, encChunk);
    final decChunk2 = secret_stream.pull(pullState, encChunk2);

    expect(message, decChunk.msg);
    expect(message2, decChunk2.msg);
  });

    final initPush = secret_stream.initPush(key);
    final encChunk = secret_stream.push(initPush.state, message);

    final pullState = secret_stream.initPull(initPush.header, key);
    final decChunk = secret_stream.pull(pullState, encChunk);

    expect(message, decChunk.msg);
  });
}
