import 'dart:convert';
import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:dart_sodium/secret_box.dart';
import 'package:dart_sodium/random_bytes.dart';

class SecretBoxBenchmark extends BenchmarkBase {
  SecretBoxBenchmark() : super('SecretBoxBenchmark');
  final Uint8List message = utf8.encode('hello world');
  SecretBox box;

  @override
  void setup() {
    LibSodium.init();
    box = SecretBox.generateKey();
  }

  @override
  void run() {
    final nonce = RandomBytes().buffer(box.nonceBytes);
    final encryptResult = box.encrypt(message,nonce: nonce);
    box.decrypt(encryptResult.cipher, nonce);
  }
}

void main() {
  SecretBoxBenchmark()..report();
}
