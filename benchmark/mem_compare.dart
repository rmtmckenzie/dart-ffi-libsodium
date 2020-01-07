import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/helpers.dart';
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;

class MemoryCompareBenchmark extends BenchmarkBase {
  MemoryCompareBenchmark() : super('MemoryCompareBenchmark');
  Uint8List a, b;
  @override
  void setup() {
    sodium.init();
    a = rand_bytes.buffer(32);
    b = Uint8List.fromList(a);
  }

  @override
  void run() {
    memoryCompare(a, b);
  }
}

void main() {
  MemoryCompareBenchmark()..report();
}
