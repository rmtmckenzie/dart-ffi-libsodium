import 'dart:ffi';
import './dart_sodium_base.dart';

typedef _PwhashStrNative = Int8 Function(Pointer<Int8> out,
    Pointer<Int8> passwd, Int64 passwdLen, Int64 opsLimit, Int64 memlimit);
typedef _PwhashStrDart = int Function(Pointer<Int8> out, Pointer<Int8> passwd,
    int passwdLen, int opsLimit, int memlimit);

final _pwhashStr = libsodium
    .lookupFunction<_PwhashStrNative, _PwhashStrDart>("crypto_pwhash_str");
