import '../dart_sodium_base.dart';
import 'dart:ffi';

final buffer = libsodium.lookupFunction<
    Void Function(Pointer<Uint8> buf, Uint64 size),
    void Function(Pointer<Uint8> buf, int size)>("randombytes_buf");
