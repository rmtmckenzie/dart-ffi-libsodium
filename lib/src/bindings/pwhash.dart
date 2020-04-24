import 'dart:ffi';
import 'sodium.dart';

typedef _StoreNative = Int16 Function(Pointer<Uint8> out, Pointer<Uint8> passwd,
    Uint64 passwdLen, Uint64 opsLimit, IntPtr memlimit);
typedef _StoreDart = int Function(Pointer<Uint8> out, Pointer<Uint8> passwd,
    int passwdLen, int opsLimit, int memlimit);
final store =
    sodium.lookupFunction<_StoreNative, _StoreDart>("crypto_pwhash_str");

typedef _VerifyNative = Int16 Function(
    Pointer<Uint8> str, Pointer<Uint8> passwd, IntPtr passwdlen);
typedef _VerifyDart = int Function(
    Pointer<Uint8> str, Pointer<Uint8> passwd, int passwdlen);
final verify = sodium
    .lookupFunction<_VerifyNative, _VerifyDart>("crypto_pwhash_str_verify");

final needsRehash = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> str, Uint64 opsLimit, IntPtr memLimit),
    int Function(Pointer<Uint8> str, int opsLimit,
        int memLimit)>("crypto_pwhash_str_needs_rehash");

class OpsLimit {
  OpsLimit(DynamicLibrary sodium)
      : min = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_opslimit_min")(),
        moderate = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_opslimit_moderate")(),
        interactive = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_opslimit_interactive")(),
        sensitive = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_opslimit_sensitive")(),
        max = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_opslimit_max")();

  final int min;
  final int interactive;
  final int moderate;
  final int sensitive;
  final int max;
}

class MemLimit {
  MemLimit(DynamicLibrary sodium)
      : min = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_memlimit_min")(),
        moderate = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_memlimit_moderate")(),
        interactive = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_memlimit_interactive")(),
        sensitive = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_memlimit_sensitive")(),
        max = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_pwhash_memlimit_max")();

  final int min;
  final int interactive;
  final int moderate;
  final int sensitive;
  final int max;
}

final storeBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_strbytes")();
final passwdMax = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_passwd_max")();
final passwdMin = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_passwd_min")();
final bytesMax = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_bytes_max")();
final bytesMin = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_bytes_min")();

class Pwhash {}
