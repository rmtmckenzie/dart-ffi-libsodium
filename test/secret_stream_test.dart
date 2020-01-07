import 'dart:convert';

import 'package:dart_sodium/secret_stream.dart' as secret_stream;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('encrypt and decrypt message as stream', () {
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

  test('encrypt and decrypt message with additional data', () {
    final key = secret_stream.keyGen();
    final message = utf8.encode('hello world');
    final metaData = DateTime.now().millisecondsSinceEpoch;
    final encodedMetaData = utf8.encode(metaData.toString());

    final initPush = secret_stream.initPush(key);
    final encChunk = secret_stream.push(initPush.state, message,
        additionalData: encodedMetaData);

    final pullState = secret_stream.initPull(initPush.header, key);
    final decChunk = secret_stream.pull(pullState, encChunk,
        additionalData: encodedMetaData);

    expect(message, decChunk.msg);
  });
}
