import 'dart:ffi';
import './ffi_helper.dart';

import './dart_sodium_base.dart';
import 'package:meta/meta.dart';

typedef _PwhashStrNative = Int16 Function(Pointer<Int8> out,
    Pointer<Int8> passwd, Uint64 passwdLen, Uint64 opsLimit, Uint64 memlimit);
typedef _PwhashStrDart = int Function(Pointer<Int8> out, Pointer<Int8> passwd,
    int passwdLen, int opsLimit, int memlimit);

final _pwhashStr = libsodium
    .lookupFunction<_PwhashStrNative, _PwhashStrDart>("crypto_pwhash_str");

final _STRBYTES = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_strbytes")();
final _OPSLIMIT_MODERATE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_moderate")();
final _MEMLIMIT_MODERATE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_moderate")();

enum Opslimit { moderate }
enum Memlimit { moderate }
int getOpslimit(Opslimit opslimit) {
  switch (opslimit) {
    case Opslimit.moderate:
      return _OPSLIMIT_MODERATE;
    default:
      throw ArgumentError("Invalid value $opslimit");
  }
}

int getMemlimit(Memlimit memlimit) {
  switch (memlimit) {
    case Memlimit.moderate:
      return _MEMLIMIT_MODERATE;
    default:
      throw ArgumentError("Invalid value $memlimit");
  }
}

String pwhashStr(String passwd, Opslimit opslimit, Memlimit memlimit) {
  final realOpslimit = getOpslimit(opslimit);
  final realMemlimit = getMemlimit(memlimit);
  final out = allocate<Int8>(count: _STRBYTES);
  final passwdCstr = StringToCstr(passwd);
  try {
    final hashResult =
        _pwhashStr(out, passwdCstr, passwd.length, realOpslimit, realMemlimit);
    if (hashResult < 0) {
      throw Exception("dart_sodium pwhashStr failed: $hashResult");
    }
    return CstrToString(out, _STRBYTES);
  } finally {
    out.free();
    passwdCstr.free();
  }
}
