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
}
