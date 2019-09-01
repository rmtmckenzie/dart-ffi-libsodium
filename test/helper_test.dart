import 'dart:convert';
import 'dart:typed_data';

import './init.dart';
import 'package:dart_sodium/helpers.dart';
import 'package:test/test.dart';

main() {
  test("memoryCompare", () {
    init();
    final buf = utf8.encode("some memory");
    final compareBuf = Uint8List.fromList(buf);
    final isEqual = memoryCompare(buf, compareBuf);
    expect(isEqual, true);
  });
}
