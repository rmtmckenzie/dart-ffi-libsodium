import 'dart:ffi';
import '../dart_sodium_base.dart';
import '../ffi_helper.dart';

typedef _StoreNative = Int16 Function(CString out, CString passwd,
    Uint64 passwdLen, Uint64 opsLimit, Uint64 memlimit);
typedef _StoreDart = int Function(
    CString out, CString passwd, int passwdLen, int opsLimit, int memlimit);
final store =
    libsodium.lookupFunction<_StoreNative, _StoreDart>("crypto_pwhash_str");

typedef _StoreVerifyNative = Int16 Function(
    CString str, CString passwd, IntPtr passwdlen);
typedef _StoreVerifyDart = int Function(
    CString str, CString passwd, int passwdlen);
final storeVerify =
    libsodium.lookupFunction<_StoreVerifyNative, _StoreVerifyDart>(
        "crypto_pwhash_str_verify");

abstract class OpsLimit {
  static final min =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_opslimit_min")();
  static final interactive =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_opslimit_interactive")();
  static final moderate =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_opslimit_moderate")();
  static final sensitive =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_opslimit_sensitive")();
  static final max =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_opslimit_max")();
}

abstract class MemLimit {
  static final min =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_memlimit_min")();
  static final interactive =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_memlimit_interactive")();
  static final moderate =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_memlimit_moderate")();
  static final sensitive =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_memlimit_sensitive")();
  static final max =
      libsodium.lookupFunction<Uint64 Function(), int Function()>(
          "crypto_pwhash_memlimit_max")();
}

final strBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_strbytes")();
