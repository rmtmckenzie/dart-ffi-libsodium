import 'sodium.dart';
import 'dart:ffi';

final seedBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'randombytes_seedbytes')();

final buffer = sodium.lookupFunction<
    Void Function(Pointer<Void> buf, IntPtr size),
    void Function(Pointer<Void> buf, int size)>("randombytes_buf");

final bufferDeterministic = sodium.lookupFunction<
    Void Function(Pointer<Void> buf, IntPtr size, Pointer<Uint8>),
    void Function(Pointer<Void> buf, int size,
        Pointer<Uint8>)>('randombytes_buf_deterministic');
