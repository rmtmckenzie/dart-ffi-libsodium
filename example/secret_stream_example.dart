import 'dart:convert';

import 'package:dart_sodium/secret_stream.dart' as secret_stream;

void main(List<String> args) {
  final key = secret_stream.keyGen();
  final message = utf8.encode('hello world');
  final message2 = utf8.encode('hello to the world');

  final pushStream = secret_stream.PushStream(key);
  final encChunk = pushStream.push(message);
  final encChunk2 = pushStream.push(message2, tag: secret_stream.Tag.finalize);

  final pullStream = secret_stream.PullStream(key, pushStream.header);
  final decChunk = pullStream.pull(encChunk);
  final decChunk2 = pullStream.pull(encChunk2);
}
