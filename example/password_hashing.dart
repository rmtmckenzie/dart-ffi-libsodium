import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init();

  final password = randomBytesBuf(16);
  final hash = pwHashStr(password, OpsLimit.interactive, MemLimit.interactive);
  final decodedHash = ascii.decode(hash);
  print(decodedHash);

  final isValid = pwHashStrVerify(hash, password);
  print(isValid);
}
