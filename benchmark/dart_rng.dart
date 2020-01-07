import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'dart:math';

class RandomBytesBenchmark extends BenchmarkBase {
  RandomBytesBenchmark() : super('RandomBytesBenchmark');
  final rng = Random.secure();
  final randomNumbers = Uint8List(32).buffer.asInt32x4List();
  @override
  void run() {
    for (var i = 0; i < randomNumbers.length; i++) {
      randomNumbers[i] = Int32x4(rng.nextInt(255), rng.nextInt(255),
          rng.nextInt(255), rng.nextInt(255));
    }
  }
}

void main() {
  RandomBytesBenchmark()..report();
}
