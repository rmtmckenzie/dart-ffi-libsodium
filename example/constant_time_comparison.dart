import 'dart:typed_data';

import 'package:dart_sodium/helpers.dart';

void main() {
  final first = Uint8List.fromList([1, 2, 3, 4, 5]);
  final second = Uint8List.fromList([]);
  final firstCopy = Uint8List.fromList(first);

  // warmup
  memoryCompare(first, second);

  final watch = Stopwatch();
  watch.start();
  memoryCompare(first, second);
  watch.stop();
  print("different buffers - ${watch.elapsed}");

  watch.start();
  memoryCompare(first, firstCopy);
  watch.stop();
  print("same buffers - ${watch.elapsed}");
}
