import 'package:ffi_helper/ffi_helper.dart';

extension ZeroList on List<int> {
  void fillZero() {
    if (isEmpty) {
      return;
    }
    fillRange(0, length, 0);
  }
}

extension FilledZeroArray on MemoryArray {
  void freeZero() {
    ZeroList(view).fillZero();
    free();
  }
}

void assertArgument<T>(T value, T expected, [String name, String message]) {
  if (value != expected) {
    throw ArgumentError.value(value, name, message);
  }
}
