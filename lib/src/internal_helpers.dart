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
void checkExpectedLengthOf(int actual, int expected,
    [String name, String message]) {
  if (actual != expected) {
    message ??= '$name must be $expected bytes long, but is $actual bytes';
    throw ArgumentError(message);
  }
}
