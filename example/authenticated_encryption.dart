import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init();

  final key = secretBoxKeygen();
  final plaintext = ascii.encode("my plaintext");
  final nonce = randomBytesBuf(secretBoxNonceBytes);
  final ciphertext = secretBoxEasy(plaintext, nonce, key);
  final encodedCipertext = base64Encode(ciphertext);
  print(encodedCipertext);

  final decrypted = secretBoxOpenEasy(ciphertext, nonce, key);
  final decoded = ascii.decode(decrypted);
  print(decoded);
}
