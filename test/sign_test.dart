import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_sodium/sign.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final sign = Sign();
  final signDetached = SignDetached();

  test('Sign and verify a message', () {
    final keyPair = KeyPair();
    final message = utf8.encode('hello world');

    final signedMessage = sign.sign(message, keyPair.secretKey);
    final openedMessage = sign.open(signedMessage, keyPair.publicKey);

    expect(openedMessage, message);
  });

  test('sign and verify a multi-part message', () {
    final keyPair = KeyPair();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');

    final signStream = SignStream();
    signStream.update(message);
    signStream.update(message2);
    final signature = signStream.finalize(keyPair.secretKey);

    final verifyStream = VerifyStream();
    verifyStream.update(message);
    verifyStream.update(message2);
    final isValid = verifyStream.verify(signature, keyPair.publicKey);
    expect(isValid, true);
  });

  test('Sign and verify a detached message', () {
    final keyPair = KeyPair();
    final message = Uint8List.fromList(utf8.encode('hello world'));

    final signature = signDetached.sign(message, keyPair.secretKey);
    final isValid = signDetached.verify(message, signature, keyPair.publicKey);

    expect(isValid, true);
  });
}
