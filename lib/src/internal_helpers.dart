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

/// Throws [ArgumentError] if simple equality check [==] between
/// [value] and [expected] fails.
void checkExpectedArgument(Object argument, Object expected,
    [String name, String message]) {
  if (argument != expected) {
    throw ArgumentError.value(argument, name, message);
  }
}
