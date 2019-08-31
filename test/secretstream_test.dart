import 'dart:convert';

import 'package:dart_sodium/src/dart_sodium_base.dart';
import 'package:test/test.dart';
import 'package:dart_sodium/secretstream.dart';

main() {
  test("encrypt and decrypt chunks", () {
    init();
    Encryptor encr;
    Decryptor decr;
    try {
      final key = Encryptor.keyGen();
      encr = Encryptor(key);
      final msg1 = utf8.encode("first message");
      final msg2 = utf8.encode("second message");
      final chunk1 = encr.push(msg1);
      final chunk2 = encr.push(msg2, tag: Tag.finish);

      decr = Decryptor(key, encr.header);
      final pull1 = decr.pull(chunk1);
      expect(pull1.decryptedChunk, chunk1);
      expect(pull1.tag, Tag.message);

      final pull2 = decr.pull(chunk2);
      expect(pull2.decryptedChunk, chunk2);
      expect(pull2.tag, Tag.finish);
    } finally {
      encr.close();
      decr.close();
    }
  });
}
