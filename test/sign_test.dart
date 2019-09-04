import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_sodium/public_key_crypto.dart';
import 'package:test/test.dart';

import 'init.dart';

main() {
  group("StreamSigner", () {
    KeyPair keys;
    StreamSigner signer;
    Uint8List msg1;
    Uint8List msg2;

    setUpAll(() {
      init();
      keys = Signer.keyPair();
      signer = StreamSigner(keys.secretKey);
      msg1 = utf8.encode("hello ");
      msg2 = utf8.encode("world");
    });

    tearDownAll(() {
      signer.close();
    });

    test("create stream and verify signature", () {
      signer.update(msg1);
      signer.update(msg2);
      final sig = signer.finish();
      final isValid = signer.verify(sig, keys.publicKey);
      expect(isValid, true);
    });
  });

  group('Signer', () {
    KeyPair keys;
    Signer signer;
    Uint8List msg;

    setUpAll(() {
      init();
      keys = Signer.keyPair();
      signer = Signer(keys.secretKey);
      msg = utf8.encode("hello world");
    });

    tearDownAll(() {
      signer.close();
    });

    test("sign message and verify signature", () {
      final sigMsg = signer.sign(msg);
      final openedMsg = Signer.open(sigMsg, keys.publicKey);
      expect(openedMsg, msg);
    });
  });
}
