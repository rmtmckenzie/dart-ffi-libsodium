import '../dart_sodium_base.dart';
import '../ffi_helper.dart';
import 'dart:ffi';

typedef _MemCmpNative = Int16 Function(
    Pointer<Uint8> b1, Pointer<Uint8> b2, Uint64 len);
typedef _MemCmpDart = int Function(
    Pointer<Uint8> b1, Pointer<Uint8> b2, int len);
final memoryCompare =
    libsodium.lookupFunction<_MemCmpNative, _MemCmpDart>("sodium_memcmp");
