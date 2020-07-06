import 'dart:convert';

import 'package:dart_sodium/secret_stream.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final secretStream = SecretStream();

  test('encrypt and decrypt message as stream', () {
    final key = secretStream.keyGen();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');

    final pushStream = secretStream.push(key);
    final encChunk = pushStream.push(message);
    final encChunk2 = pushStream.push(message2, tag: Tag.finalize);

    final pullStream = secretStream.pull(key, pushStream.header);
    final decChunk = pullStream.pullWithTag(encChunk);

    expect(decChunk.value, message);
    expect(decChunk.tag, Tag.message);

    final decChunk2 = pullStream.pullWithTag(encChunk2);

    expect(decChunk2.value, message2);
    expect(decChunk2.tag, Tag.finalize);
  });

  test('encrypt and decrypt message with additional data', () {
    final key = secretStream.keyGen();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');
    final metaData = DateTime.now().millisecondsSinceEpoch;
    final metaData2 = DateTime.now().millisecondsSinceEpoch;
    final encodedMetaData = utf8.encode(metaData.toString());
    final encodedMetaData2 = utf8.encode(metaData2.toString());

    final pushStream = secretStream.push(key);
    final encChunk = pushStream.push(message, additionalData: encodedMetaData);
    final encChunk2 = pushStream.push(message2, additionalData: encodedMetaData2, tag: Tag.finalize);

    final pullStream = secretStream.pull(key, pushStream.header);
    final decChunk = pullStream.pull(encChunk, additionalData: encodedMetaData);

    expect(message, decChunk);

    final decChunk2 = pullStream.pullWithTag(encChunk2, additionalData: encodedMetaData2);
    expect(decChunk2.value, message2);
    expect(decChunk2.tag, Tag.finalize);
  });
}
