import 'dart:convert';
import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/secret_box.dart' as secret_box;
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;

class SecretBoxBenchmark extends BenchmarkBase {
  SecretBoxBenchmark() : super('SecretBoxBenchmark');
  final Uint8List message = utf8.encode('hello world');
  final Uint8List key = secret_box.keyGen();
  @override
  void setup() {
    sodium.init();
  }

  @override
  void run() {
    final nonce = rand_bytes.buffer(secret_box.nonceBytes);
    final encrypted = secret_box.easy(message, nonce, key);
    secret_box.openEasy(encrypted, nonce, key);
  }
}

void main() {
  SecretBoxBenchmark()..report();
}
