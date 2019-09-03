import 'dart:convert';

import './init.dart';
import 'package:test/test.dart';
import 'package:dart_sodium/secret_key_crypto.dart';

main() {
  test("encrypt and decrypt chunks", () {
    init();
    StreamEncryptor encr;
    StreamDecryptor decr;
    try {
      final key = StreamEncryptor.keyGen();
      encr = StreamEncryptor(key);
      final msg1 = utf8.encode("first message");
      final msg2 = utf8.encode("second message");
      final chunk1 = encr.push(msg1);
      final chunk2 = encr.push(msg2, tag: Tag.finish);

      decr = StreamDecryptor(key, encr.header);
      final pull1 = decr.pull(chunk1);
      expect(pull1.decryptedChunk, msg1);
      expect(pull1.tag, Tag.message);

      final pull2 = decr.pull(chunk2);
      expect(pull2.decryptedChunk, msg2);
      expect(pull2.tag, Tag.finish);
    } finally {
      encr?.close();
      decr?.close();
    }
  });
}
