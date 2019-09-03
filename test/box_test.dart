import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_sodium/box.dart';
import 'package:dart_sodium/random.dart';
import 'package:test/test.dart';

import 'init.dart';

main() {
  group("Box", () {
    KeyPair keys;
    Box box;
    Uint8List msg, nonce;

    setUpAll(() {
      init();
      keys = Box.keyPair();
      box = Box(keys.secretKey);
      msg = utf8.encode("hello world");
      nonce = buffer(Box.nonceBytes);
    });

    tearDownAll(() {
      box.close();
    });
    test("encrypt and decrypt a message", () {
      final ciphertext = box.easy(msg, nonce, keys.publicKey);
      final decrypted = box.openEasy(ciphertext, nonce, keys.publicKey);
      expect(msg, decrypted);
    });

    test("encrypt and decrypt a message in detached mode", () {
      final detached = box.detached(msg, nonce, keys.publicKey);
      final decrypted = box.openDetached(
          detached.ciphertext, nonce, detached.authTag, keys.publicKey);
      expect(decrypted, msg);
    });
  });

  group("BoxNumerous", () {
    KeyPair keys;
    BoxNumerous box;
    Uint8List msg, nonce;

    setUpAll(() {
      init();
      keys = Box.keyPair();
      box = BoxNumerous(keys.publicKey, keys.secretKey);
      msg = utf8.encode("hello world");
      nonce = buffer(Box.nonceBytes);
    });

    tearDownAll(() {
      box.close();
    });
    test("encrypt and decrypt a message", () {
      final ciphertext = box.easy(msg, nonce);
      final decrypted = box.openEasy(ciphertext, nonce);
      expect(msg, decrypted);
    });

    test("encrypt and decrypt a message in detached mode", () {
      final detached = box.detached(msg, nonce);
      final decrypted =
          box.openDetached(detached.ciphertext, nonce, detached.authTag);
      expect(decrypted, msg);
    });
  });
}
