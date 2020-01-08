import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:dart_sodium/sodium.dart' as sodium;
import 'package:dart_sodium/random_bytes.dart' as rand_bytes;

class ConstantTimeListCompareBenchmark extends BenchmarkBase {
  ConstantTimeListCompareBenchmark()
      : super('ConstantTimeListCompareBenchmark');
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
    final ax4 = a.buffer.asInt32x4List();
    final bx4 = b.buffer.asInt32x4List();
    for (var i = 0; i < ax4.length; i++) {
      ax4[i] == bx4[i];
    }
  }
}

void main() {
  ConstantTimeListCompareBenchmark()..report();
}
