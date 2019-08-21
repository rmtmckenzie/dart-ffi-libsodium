import 'dart:convert';
import 'dart:ffi';
import './ffi_helper.dart';

import './dart_sodium_base.dart';

typedef _PwhashStrNative = Int16 Function(Pointer<Int8> out,
    Pointer<Int8> passwd, Uint64 passwdLen, Uint64 opsLimit, Uint64 memlimit);
typedef _PwhashStrDart = int Function(Pointer<Int8> out, Pointer<Int8> passwd,
    int passwdLen, int opsLimit, int memlimit);

final _pwhashStr = libsodium
    .lookupFunction<_PwhashStrNative, _PwhashStrDart>("crypto_pwhash_str");

typedef _PwhashStrVerifyNative = Int16 Function(
    Pointer<Int8> str, Pointer<Int8> passwd, Uint64 passwdlen);
typedef _PwhashStrVerifyDart = int Function(
    Pointer<Int8> str, Pointer<Int8> passwd, int passwdlen);

final _pwhashStrVerify =
    libsodium.lookupFunction<_PwhashStrVerifyNative, _PwhashStrVerifyDart>(
        "crypto_pwhash_str_verify");

final pwHashStrBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
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

class OpsLimit {
  static final min = _OPSLIMIT_MIN;
  static final interactive = _OPSLIMIT_INTERACTIVE;
  static final moderate = _OPSLIMIT_MODERATE;
  static final sensitive = _OPSLIMIT_SENSITIVE;
  static final max = _OPSLIMIT_MAX;
}

class MemLimit {
  static final min = _MEMLIMIT_MIN;
  static final interactive = _MEMLIMIT_INTERACTIVE;
  static final moderate = _MEMLIMIT_MODERATE;
  static final sensitive = _MEMLIMIT_SENSITIVE;
  static final max = _MEMLIMIT_MAX;
}

String pwHashStr(String passwd, int opslimit, int memlimit) {
  assert(
      opslimit == OpsLimit.min ||
          opslimit == OpsLimit.interactive ||
          opslimit == OpsLimit.moderate ||
          opslimit == OpsLimit.interactive ||
          opslimit == OpsLimit.max,
      "opslimit must be a valid value from OpsLimit");
  assert(
      memlimit == MemLimit.min ||
          memlimit == MemLimit.interactive ||
          memlimit == MemLimit.moderate ||
          memlimit == MemLimit.interactive ||
          memlimit == MemLimit.max,
      "memlimit must be a valid value from MemLimit");
  Pointer<Int8> out;
  Pointer<Int8> passwdCstr;
  try {
    out = allocate<Int8>(count: pwHashStrBytes);
    passwdCstr = StringToCstr(passwd);
    final hashResult =
        _pwhashStr(out, passwdCstr, passwd.length, opslimit, memlimit);
    if (hashResult < 0) {
      throw Exception(
          "pwhashStr failed. Please make sure opslimit is a value from OpsLimit and memlimit is a value from MemLimit. For debugging enable asserts.");
    }
    return CstrToString(out, pwHashStrBytes);
  } finally {
    out?.free();
    passwdCstr?.free();
  }
}

bool pwHashStrVerify(String hash, String passwd) {
  assert(hash.length > pwHashStrBytes,
      "The provided hash is longer than expected");
  Pointer<Int8> hashPtr;
  Pointer<Int8> passwdPtr;
  try {
    hashPtr = allocate(count: pwHashStrBytes);
    {
      var i = 0;
      final buf = ascii.encode(hash);
      for (; i < hash.length; i++) {
        hashPtr.elementAt(i).store(buf[i]);
      }
      hashPtr.elementAt(i + 1).store(0);
    }
    passwdPtr = StringToCstr(passwd);
    final verifyResult = _pwhashStrVerify(hashPtr, passwdPtr, passwd.length);
    if (verifyResult == -1) {
      return false;
    }
    return true;
  } finally {
    hashPtr?.free();
    passwdPtr?.free();
  }
}
