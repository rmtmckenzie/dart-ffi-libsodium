import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init();

  final key = authKeyGen();
  final msg = randomBytesBuf(16);
  final tag = auth(msg, key);
  final encodedTag = base64Encode(tag);
  print(encodedTag);

  final isValid = authVerify(tag, msg, key);
  print(isValid);
}
