import 'dart:math';
import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/random_bytes.dart';
import 'package:dart_sodium/sodium.dart';

class RandomBytesBenchmark extends BenchmarkBase {
  RandomBytesBenchmark() : super('RandomBytesBenchmark');

  RandomBytes randomBytes;

  @override
  void setup() {
    LibSodium.init();
    randomBytes = RandomBytes();
  }

  @override
  void run() {
    randomBytes.buffer(32);
  }
}

const int MAX_UINT_8 = 1 << 8;

class DartRandomBenchmark extends BenchmarkBase {
  DartRandomBenchmark() : super('DartRandomBenchmark');

  Random random;

  @override
  void setup() {
    random = Random.secure();
  }

  @override
  void run() {
    Uint8List.fromList(List.generate(32, (index) => random.nextInt(MAX_UINT_8)));
  }
}

class DartRandomLoopBenchmark extends BenchmarkBase {
  DartRandomLoopBenchmark() : super('DartRandomLoopBenchmark');

  Random random;

  @override
  void setup() {
    random = Random.secure();
  }

  @override
  void run() {
    final list = Uint8List(32);
    for (var i = 0; i < 32; ++i) {
      list[i] = random.nextInt(MAX_UINT_8);
    }
  }
}

void main() {
  RandomBytesBenchmark()..report();
  DartRandomBenchmark()..report();
  DartRandomLoopBenchmark()..report();
}
