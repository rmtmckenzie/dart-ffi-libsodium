import 'dart:convert';

import 'package:dart_sodium/aead.dart';
import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final randomBytes = RandomBytes();

  test('encrypt and decrypt individual message', () {
    final aead = AeadXChacha20Poly1305IETF.generateKey();
    final message = utf8.encode('hello world');
    final nonce = randomBytes.buffer(aead.nonceBytes);

    final encrypted = aead.encrypt(message, nonce: nonce);
    final decrypted = aead.decrypt(encrypted.cipher, nonce);

    expect(message, decrypted);
  });

  test('encrypt and decrypt individual message w/ autogen nonce', () {
    final aead = AeadXChacha20Poly1305IETF.generateKey();
    final message = utf8.encode('goodbye world');

    final encrypted = aead.encrypt(message);
    final decrypted = aead.decrypt(encrypted.cipher, encrypted.nonce);

    expect(message, decrypted);
  });


  test('encrypt and decrypt w/ passed in key', () {
    final aead1 = AeadXChacha20Poly1305IETF.generateKey();
    final aead2 = AeadXChacha20Poly1305IETF.fromKey(aead1.key);
    final message = utf8.encode('what\'s up world');

    final encrypted = aead1.encrypt(message);
    final decrypted = aead2.decrypt(encrypted.cipher, encrypted.nonce);

    expect(message, decrypted);
  });

  test('encrypt w/ passed in key and decrypt', () {
    final aead2 = AeadXChacha20Poly1305IETF.generateKey();
    final aead1 = AeadXChacha20Poly1305IETF.fromKey(aead2.key);
    final message = utf8.encode('here we go again');

    final encrypted = aead1.encrypt(message);
    final decrypted = aead2.decrypt(encrypted.cipher, encrypted.nonce);

    expect(message, decrypted);
  });

  test('encrypt and decrypt with addional data', () {
    final aead = AeadXChacha20Poly1305IETF.generateKey();
    final message = utf8.encode('please work');
    final additionalData = utf8.encode('or else');

    final encrypted = aead.encrypt(message, additionalData: additionalData);
    final decrypted = aead.decrypt(encrypted.cipher, encrypted.nonce, additionalData: additionalData);

    expect(message, decrypted);
  });
}
