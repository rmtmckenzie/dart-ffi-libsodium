import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';

void main() {
  init();

  final password = RandomBytes.buf(16);
  final hash = pwHash.str(password, OpsLimit.interactive, MemLimit.interactive);

  final isValid = pwHash.verify(hash, password);
}
