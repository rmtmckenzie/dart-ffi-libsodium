import 'dart:convert';

import 'package:dart_sodium/sign.dart' as sign;
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:test/test.dart';

void main() {
  sodium.init();
  test('Sign and verify a message', () {
    final keyPair = sign.KeyPair.generate();
    final message = utf8.encode('hello world');

    final signedMessage = sign.sign(message, keyPair.secretKey);
    final openedMessage = sign.open(signedMessage, keyPair.publicKey);

    expect(openedMessage, message);
  });

  test('sign and verify a multi-part message', () {
    final keyPair = sign.KeyPair.generate();
    final message = utf8.encode('hello world');
    final message2 = utf8.encode('hello to the world');

    final signStream = sign.SignStream();
    signStream.update(message);
    signStream.update(message2);
    final signature = signStream.finalize(keyPair.secretKey);

    final verifyStream = sign.VerifyStream();
    verifyStream.update(message);
    verifyStream.update(message2);
    final isValid = verifyStream.verify(signature, keyPair.publicKey);
    expect(isValid, true);
  });
}
