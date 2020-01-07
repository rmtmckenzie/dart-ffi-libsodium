import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;

class RandomBytesBenchmark extends BenchmarkBase {
  RandomBytesBenchmark() : super('RandomBytesBenchmark');

  @override
  void setup() {
    sodium.init();
  }

  @override
  void run() {
    rand_bytes.buffer(32);
  }
}

void main() {
  RandomBytesBenchmark()..report();
}
