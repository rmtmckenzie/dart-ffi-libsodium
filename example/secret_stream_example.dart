import 'dart:convert';

import 'package:dart_sodium/secret_stream.dart';

void main(List<String> args) {
  final key = SecretStream().keyGen();
  final message = utf8.encode('hello world');
  final message2 = utf8.encode('hello to the world');

  var pushStream = PushStream(key);

  final encChunk = pushStream.push(message);
  final encChunk2 = pushStream.push(message2, tag: Tag.finalize);

  final pullStream = PullStream(key, pushStream.header);
  final decChunk = pullStream.pull(encChunk);
  final decChunk2 = pullStream.pull(encChunk2);
}
