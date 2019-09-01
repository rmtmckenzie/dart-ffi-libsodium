import 'dart:convert';

import 'package:dart_sodium/secretstream.dart' as secretstream;
import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init("./libsodium");
  final key = secretstream.keyGen();
  final encr = secretstream.Encryptor(key);
  final decr = secretstream.Decryptor(key, encr.header);

  final msg1 = utf8.encode("hello");
  final msg2 = utf8.encode("world");
  try {
    final chunk1 = encr.push(msg1);
    final chunk2 = encr.push(msg2, tag: secretstream.Tag.finish);

    final pull1 = decr.pull(chunk1);
    final pull2 = decr.pull(chunk2);

    assert(pull2.tag == secretstream.Tag.finish);
    assert(pull1.decryptedChunk == msg1);
    assert(pull2.decryptedChunk == msg2);
  } finally {
    encr.close();
    decr.close();
  }
}
