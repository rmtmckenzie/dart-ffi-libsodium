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

    final pushStream = secret_stream.PushStream(key);
    final encChunk = pushStream.push(message);
    final encChunk2 =
        pushStream.push(message2, tag: secret_stream.Tag.finalize);

    final pullStream = secret_stream.PullStream(key, pushStream.header);
    final decChunk = pullStream.pull(encChunk);

    expect(message, decChunk);
    expect(pullStream, secret_stream.Tag.message);

    final decChunk2 = pullStream.pull(encChunk2);

    expect(message2, decChunk2);
    expect(pullStream, secret_stream.Tag.finalize);
  });

  test('encrypt and decrypt message with additional data', () {
    final key = secret_stream.keyGen();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');
    final metaData = DateTime.now().millisecondsSinceEpoch;
    final metaData2 = DateTime.now().millisecondsSinceEpoch;
    final encodedMetaData = utf8.encode(metaData.toString());
    final encodedMetaData2 = utf8.encode(metaData2.toString());

    final pushStream = secret_stream.PushStream(key);
    final encChunk = pushStream.push(message, additionalData: encodedMetaData);
    final encChunk2 = pushStream.push(message2,
        additionalData: encodedMetaData2, tag: secret_stream.Tag.finalize);

    final pullStream = secret_stream.PullStream(key, pushStream.header);
    final decChunk = pullStream.pull(encChunk, additionalData: encodedMetaData);

    expect(message, decChunk);
    expect(pullStream.tag, secret_stream.Tag.message);

    final decChunk2 =
        pullStream.pull(encChunk2, additionalData: encodedMetaData2);
    expect(message2, decChunk2);
    expect(pullStream.tag, secret_stream.Tag.finalize);
  });
}
