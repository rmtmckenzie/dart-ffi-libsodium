import 'dart:ffi';

import '../dart_sodium_base.dart';

final memoryLock = libsodium.lookupFunction<
    Int16 Function(Pointer<Void> addr, IntPtr len),
    int Function(Pointer<Void> addr, int len)>("sodium_mlock");
final memoryUnlock = libsodium.lookupFunction<
    Int16 Function(Pointer<Void> addr, IntPtr len),
    int Function(Pointer<Void> addr, int len)>("sodium_munlock");
