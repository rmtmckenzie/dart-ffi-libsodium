import 'dart:ffi';

import 'sodium.dart';

final zero = sodium.lookupFunction<
    Void Function(Pointer<Void> ptr, IntPtr size),
    void Function(Pointer<Void> ptr, int size)>("sodium_memzero");

final lock = sodium.lookupFunction<
    Int16 Function(Pointer<Void> addr, IntPtr len),
    int Function(Pointer<Void> addr, int len)>("sodium_mlock");
final unlock = sodium.lookupFunction<
    Int16 Function(Pointer<Void> addr, IntPtr len),
    int Function(Pointer<Void> addr, int len)>("sodium_munlock");

final malloc = sodium.lookupFunction<Pointer<Void> Function(IntPtr size),
    Pointer<Void> Function(int size)>("sodium_malloc");
final allocArray = sodium.lookupFunction<
    Pointer<Void> Function(IntPtr count, IntPtr size),
    Pointer<Void> Function(int count, int size)>("sodium_allocarray");
final free = sodium.lookupFunction<Void Function(Pointer<Void> ptr),
    void Function(Pointer<Void> ptr)>("sodium_free");

final noAccess = sodium.lookupFunction<Int16 Function(Pointer<Void> ptr),
    int Function(Pointer<Void> ptr)>("sodium_mprotect_noaccess");

final reaOnly = sodium.lookupFunction<Int16 Function(Pointer<Void> ptr),
    int Function(Pointer<Void> ptr)>("sodium_mprotect_readonly");

final readWrite = sodium.lookupFunction<Int16 Function(Pointer<Void> ptr),
    int Function(Pointer<Void> ptr)>("sodium_mprotect_readwrite");
