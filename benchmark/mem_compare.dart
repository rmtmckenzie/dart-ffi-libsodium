import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:dart_sodium/helpers.dart';
import 'package:dart_sodium/random_bytes.dart';

class MemoryCompareBenchmark extends BenchmarkBase {
  MemoryCompareBenchmark() : super('MemoryCompareBenchmark');
  Uint8List a, b;
  @override
  void setup() {
    LibSodium.init();
    a = RandomBytes().buffer(32);
    b = Uint8List.fromList(a);
  }

  @override
  void run() {
    Helpers().memoryCompare(a, b);
  }
}

void main() {
  MemoryCompareBenchmark()..report();
}
