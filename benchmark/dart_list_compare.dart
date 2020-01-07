import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/helpers.dart';
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;

class RandomBytesBenchmark extends BenchmarkBase {
  RandomBytesBenchmark() : super('RandomBytesBenchmark');
  Uint8List a, b;
  @override
  void setup() {
    sodium.init();
    a = rand_bytes.buffer(32);
    b = Uint8List.fromList(a);
    b[5] == a[5] + 1;
  }

  @override
  void run() {
    for (var i = 0; i < a.length; i++) {
      if (a[i] == b[i]) {}
    }
  }
}

void main() {
  RandomBytesBenchmark()..report();
}
