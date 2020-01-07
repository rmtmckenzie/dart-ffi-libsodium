import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'dart:math';

class RandomBytesBenchmark extends BenchmarkBase {
  RandomBytesBenchmark() : super('RandomBytesBenchmark');

  @override
  void run() {
    final rng = Random.secure();
    final randomNumbers = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      randomNumbers[i] = rng.nextInt(255);
    }
  }
}

void main() {
  RandomBytesBenchmark()..report();
}
