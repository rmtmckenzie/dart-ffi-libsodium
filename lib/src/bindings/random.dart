import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

final buffer = libsodium.lookupFunction<Void Function(CString buf, Uint64 size),
    void Function(CString buf, int size)>("randombytes_buf");
