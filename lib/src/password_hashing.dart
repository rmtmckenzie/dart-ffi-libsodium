import 'dart:ffi';
import './ffi_helper.dart';

import './dart_sodium_base.dart';
import 'package:meta/meta.dart';

typedef _PwhashStrNative = Int8 Function(Pointer<Uint8> out,
    Pointer<Uint8> passwd, Uint64 passwdLen, Uint64 opsLimit, Uint64 memlimit);
typedef _PwhashStrDart = int Function(Pointer<Uint8> out, Pointer<Uint8> passwd,
    int passwdLen, int opsLimit, int memlimit);

final _pwhashStr = libsodium
    .lookupFunction<_PwhashStrNative, _PwhashStrDart>("crypto_pwhash_str");

final _STRBYTES = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_strbytes")();

String pwhashStr(String passwd,
    {@required int opslimit, @required int memlimit}) {
  final Pointer<Uint8> out = allocate(count: _STRBYTES);
  final passwdCstr = StringToCstr(passwd);
  try {
    final hashResult =
        _pwhashStr(out, passwdCstr, passwd.length, opslimit, memlimit);
    if (hashResult < 0) {
      Exception("dart_sodium pwhashStr failed: $hashResult");
    }
    return CstrToString(out, passwd.length);
  } finally {
    out.free();
    passwdCstr.free();
  }
}
