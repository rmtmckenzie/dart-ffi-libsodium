import 'dart:convert';

import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:dart_sodium/pwhash.dart' as pwhash;

void main() {
  init();

  final password = rand.buf(16);
  final hash = pwhash.str(
      password, pwhash.OpsLimit.interactive, pwhash.MemLimit.interactive);

  final isValid = pwhash.verify(hash, password);
}
