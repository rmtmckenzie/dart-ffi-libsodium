import 'dart:ffi';

import '../dart_sodium_base.dart';

final memoryLock = libsodium.lookupFunction<
    Int16 Function(IntPtr addr, IntPtr len),
    int Function(int addr, int len)>("sodium_mlock");
final memoryUnlock = libsodium.lookupFunction<
    Int16 Function(IntPtr addr, IntPtr len),
    int Function(int addr, int len)>("sodium_munlock");
