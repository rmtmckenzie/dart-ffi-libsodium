import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

final randomBytesBuf = libsodium.lookupFunction<
    Void Function(Pointer<Uint8> buf, Uint64 size),
    void Function(Pointer<Uint8> buf, int size)>("randombytes_buf");
