import '../dart_sodium_base.dart';
import '../ffi_helper.dart';
import 'dart:ffi';

typedef _MemCmpNative = Int16 Function(CString b1, CString b2, Uint64 len);
typedef _MemCmpDart = int Function(CString b1, CString b2, int len);
final memCmp =
    libsodium.lookupFunction<_MemCmpNative, _MemCmpDart>("sodium_memcmp");