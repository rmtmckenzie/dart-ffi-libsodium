import 'dart:convert';
import 'package:dart_sodium/password_hash.dart' as pwhash;

void main(List<String> args) {
  final password = utf8.encode('my password');
  final hash = pwhash.store(
      password, pwhash.OpsLimit.interactive, pwhash.MemLimit.interactive);
  final isValid = pwhash.verify(hash, password);
}
