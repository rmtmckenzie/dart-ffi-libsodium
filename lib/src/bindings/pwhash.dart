import 'dart:ffi';
import '../dart_sodium_base.dart';

typedef _pwHashStrNative = Int16 Function(Pointer<Uint8> out,
    Pointer<Uint8> passwd, Uint64 passwdLen, Uint64 opsLimit, Uint64 memlimit);
typedef _pwhashStrDart = int Function(Pointer<Uint8> out, Pointer<Uint8> passwd,
    int passwdLen, int opsLimit, int memlimit);
final pwHashStr = libsodium
    .lookupFunction<_pwHashStrNative, _pwhashStrDart>("crypto_pwhash_str");

typedef _pwHashStrVerifyNative = Int16 Function(
    Pointer<Uint8> str, Pointer<Uint8> passwd, IntPtr passwdlen);
typedef _pwHashStrVerifyDart = int Function(
    Pointer<Uint8> str, Pointer<Uint8> passwd, int passwdlen);
final pwHashStrVerify =
    libsodium.lookupFunction<_pwHashStrVerifyNative, _pwHashStrVerifyDart>(
        "crypto_pwhash_str_verify");

final opsLimitModerate =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_moderate")();
final opsLimitMin = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_opslimit_min")();
final opsLimitSensitive =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_sensitive")();
final opsLimitInteractive =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_opslimit_interactive")();
final opsLimitMax = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_opslimit_max")();

final memLimitModerate =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_moderate")();
final memLimitMin = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_memlimit_min")();
final memLimitSensitive =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_sensitive")();
final memLimitInteractive =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_pwhash_memlimit_interactive")();
final memLimitMax = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_pwhash_memlimit_max")();
