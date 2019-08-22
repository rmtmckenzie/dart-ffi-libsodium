import 'dart:typed_data';

import 'package:dart_sodium/src/helpers.dart';

void main() {
  final first = Uint8List.fromList([1, 2, 3, 4, 5]);
  final second = Uint8List.fromList([]);
  final firstCopy = Uint8List.fromList(first);

  // warmup
  memCmp(first, second);

  final watch = Stopwatch();
  watch.start();
  memCmp(first, second);
  watch.stop();
  print("different buffers - ${watch.elapsed}");

  watch.start();
  memCmp(first, firstCopy);
  watch.stop();
  print("same buffers - ${watch.elapsed}");
}
