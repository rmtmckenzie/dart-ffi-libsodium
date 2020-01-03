import 'sodium.dart';
import 'dart:ffi';

final buffer = sodium.lookupFunction<
    Void Function(Pointer<Void> buf, IntPtr size),
    void Function(Pointer<Void> buf, int size)>("randombytes_buf");
