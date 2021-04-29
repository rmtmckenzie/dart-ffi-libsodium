import 'dart:ffi' as ffi;
import 'dart:ffi';
import 'dart:typed_data';

import 'package:dart_sodium/src/helpers/memory_array.dart';

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

extension Uint8ListToArray on Uint8List {
  Uint8Array get asArray => Uint8Array.fromTypedList(this);
}

class NullArray<T extends ffi.NativeType> extends MemoryArray<T> {
  NullArray() : super.nullPointer();

  static const List<int> _view = [];

  @override
  Uint8List get view => _view;
}

/// Throws [ArgumentError] if simple equality check [==] between
/// [actual] and [expected] fails.
void checkExpectedLengthOf(int actual, int expected, String name) {
  if (actual != expected) {
    throw ArgumentError('$name must be $expected bytes long, but is $actual bytes');
  }
}

/// Throws [ArgumentError] if [actual] is not between min and max (inclusive)
void checkInRange(int actual, int min, int max, String name) {
  if (actual < min || max < actual) {
    throw ArgumentError('$name must be between $min and $max, but is $actual');
  }
}

R free1<T extends NativeType, R>(MemoryArray<T> a, R Function(MemoryArray<T> a) operation) {
  try {
    return operation(a ?? NullArray<T>());
  } finally {
    a?.free();
  }
}

R free2<T1 extends NativeType, T2 extends NativeType, R>(
    MemoryArray<T1> a1, MemoryArray<T2> a2, R Function(MemoryArray<T1> a1, MemoryArray<T2> a2) operation) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
    );
  } finally {
    a2?.free();
    a1?.free();
  }
}

R free3<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, R>(MemoryArray<T1> a1, MemoryArray<T2> a2,
    MemoryArray<T3> a3, R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3) operation) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
    );
  } finally {
    a3?.free();
    a2?.free();
    a1?.free();
  }
}

R freeZero1<T extends NativeType, R>(MemoryArray<T> a, R Function(MemoryArray<T> a) operation) {
  try {
    return operation(a ?? NullArray<T>());
  } finally {
    a?.freeZero();
  }
}

R freeZero2<T1 extends NativeType, T2 extends NativeType, R>(
    MemoryArray<T1> a1, MemoryArray<T2> a2, R Function(MemoryArray<T1> a1, MemoryArray<T2> a2) operation) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
    );
  } finally {
    a2?.freeZero();
    a1?.freeZero();
  }
}

R freeZero3<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, R>(
    MemoryArray<T1> a1,
    MemoryArray<T2> a2,
    MemoryArray<T3> a3,
    R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3) operation) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
    );
  } finally {
    a3?.freeZero();
    a2?.freeZero();
    a1?.freeZero();
  }
}

R free1freeZero1<T1 extends NativeType, T2 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2) operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
    );
  } finally {
    a2?.freeZero();
    a1?.free();
  }
}

R free1freeZero2<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3) operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
    );
  } finally {
    a3?.freeZero();
    a2?.freeZero();
    a1?.free();
  }
}

R free2freeZero1<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3) operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
    );
  } finally {
    a3?.freeZero();
    a2?.free();
    a1?.free();
  }
}

R free2freeZero2<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, T4 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  MemoryArray<T4> a4,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3, MemoryArray<T4> a4) operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
      a4 ?? NullArray<T4>(),
    );
  } finally {
    a4?.freeZero();
    a3?.freeZero();
    a2?.free();
    a1?.free();
  }
}

R free2freeZero3<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, T4 extends NativeType,
    T5 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  MemoryArray<T4> a4,
  MemoryArray<T5> a5,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3, MemoryArray<T4> a4, MemoryArray<T5> a5)
      operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
      a4 ?? NullArray<T4>(),
      a5 ?? NullArray<T5>(),
    );
  } finally {
    a5?.freeZero();
    a4?.freeZero();
    a3?.freeZero();
    a2?.free();
    a1?.free();
  }
}

R free3freeZero1<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, T4 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  MemoryArray<T4> a4,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3, MemoryArray<T4> a4) operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
      a4 ?? NullArray<T4>(),
    );
  } finally {
    a4?.freeZero();
    a3?.free();
    a2?.free();
    a1?.free();
  }
}

R free4freeZero1<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, T4 extends NativeType,
    T5 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  MemoryArray<T4> a4,
  MemoryArray<T5> a5,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3, MemoryArray<T4> a4, MemoryArray<T5> a5)
      operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
      a4 ?? NullArray<T4>(),
      a5 ?? NullArray<T5>(),
    );
  } finally {
    a5?.freeZero();
    a4?.free();
    a3?.free();
    a2?.free();
    a1?.free();
  }
}

R free5freeZero1<T1 extends NativeType, T2 extends NativeType, T3 extends NativeType, T4 extends NativeType,
    T5 extends NativeType, T6 extends NativeType, R>(
  MemoryArray<T1> a1,
  MemoryArray<T2> a2,
  MemoryArray<T3> a3,
  MemoryArray<T4> a4,
  MemoryArray<T5> a5,
  MemoryArray<T6> a6,
  R Function(MemoryArray<T1> a1, MemoryArray<T2> a2, MemoryArray<T3> a3, MemoryArray<T4> a4, MemoryArray<T5> a5,
          MemoryArray<T6> a6)
      operation,
) {
  try {
    return operation(
      a1 ?? NullArray<T1>(),
      a2 ?? NullArray<T2>(),
      a3 ?? NullArray<T3>(),
      a4 ?? NullArray<T4>(),
      a5 ?? NullArray<T5>(),
      a6 ?? NullArray<T6>(),
    );
  } finally {
    a6?.freeZero();
    a5?.free();
    a4?.free();
    a3?.free();
    a2?.free();
    a1?.free();
  }
}
