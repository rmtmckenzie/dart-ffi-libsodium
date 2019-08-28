import 'dart:ffi';
import '../dart_sodium_base.dart';

typedef pwHashStrNative = Int16 Function(Pointer<Uint8> out,
    Pointer<Uint8> passwd, Uint64 passwdLen, Uint64 opsLimit, Uint64 memlimit);
typedef pwhashStrDart = int Function(Pointer<Uint8> out, Pointer<Uint8> passwd,
    int passwdLen, int opsLimit, int memlimit);
final pwHashStr = libsodium
    .lookupFunction<pwHashStrNative, pwhashStrDart>("crypto_pwhash_str");

typedef pwHashStrVerifyNative = Int16 Function(
    Pointer<Uint8> str, Pointer<Uint8> passwd, IntPtr passwdlen);
typedef pwHashStrVerifyDart = int Function(
    Pointer<Uint8> str, Pointer<Uint8> passwd, int passwdlen);
final pwHashStrVerify =
    libsodium.lookupFunction<pwHashStrVerifyNative, pwHashStrVerifyDart>(
        "crypto_pwhash_str_verify");
