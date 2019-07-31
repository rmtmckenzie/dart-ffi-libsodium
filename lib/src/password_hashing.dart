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
final _OPSLIMIT_MIN =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_min")();
final _OPSLIMIT_SENSITIVE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_sensitive")();
final _OPSLIMIT_INTERACTIVE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_interactive")();
final _OPSLIMIT_MAX =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_max")();
final _MEMLIMIT_MODERATE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_moderate")();
final _MEMLIMIT_MIN =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_min")();
final _MEMLIMIT_SENSITIVE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_sensitive")();
final _MEMLIMIT_INTERACTIVE =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_interactive")();
final _MEMLIMIT_MAX =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_max")();

enum Opslimit { min, interactive, moderate, sensitive, max }
enum Memlimit { min, interactive, moderate, sensitive, max }
int getOpslimit(Opslimit opslimit) {
  switch (opslimit) {
    case Opslimit.moderate:
      return _OPSLIMIT_MODERATE;
    case Opslimit.interactive:
      return _OPSLIMIT_INTERACTIVE;
    case Opslimit.min:
      return _OPSLIMIT_MIN;
    case Opslimit.sensitive:
      return _OPSLIMIT_SENSITIVE;
    case Opslimit.max:
      return _OPSLIMIT_MAX;
    default:
      throw ArgumentError("Invalid value $opslimit");
  }
}

int getMemlimit(Memlimit memlimit) {
  switch (memlimit) {
    case Memlimit.moderate:
      return _MEMLIMIT_MODERATE;
    case Memlimit.min:
      return _MEMLIMIT_MIN;
    case Memlimit.interactive:
      return _MEMLIMIT_INTERACTIVE;
    case Memlimit.sensitive:
      return _MEMLIMIT_SENSITIVE;
    case Memlimit.max:
      return _MEMLIMIT_MAX;
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
