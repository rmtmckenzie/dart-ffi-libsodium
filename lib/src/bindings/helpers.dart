import 'sodium.dart';
import 'dart:ffi';

typedef _MemCmpNative = Int16 Function(
    Pointer<Uint8> b1, Pointer<Uint8> b2, IntPtr len);
typedef _MemCmpDart = int Function(
    Pointer<Uint8> b1, Pointer<Uint8> b2, int len);
final memoryCompare =
    sodium.lookupFunction<_MemCmpNative, _MemCmpDart>("sodium_memcmp");
