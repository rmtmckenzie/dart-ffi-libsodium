import 'dart:ffi';

import '../dart_sodium_base.dart';

final signBytes = libsodium.lookupFunction("crypto_sign_bytes")();
final publicKeyBytes = libsodium.lookupFunction("crypto_sign_publickeybytes")();
final secretKeyBytes = libsodium.lookupFunction("crypto_sign_bytes")();
final keyPair = libsodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk)>("crypto_sign_keypair");
final seedKeyPair = libsodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk,
        Pointer<Uint8> seed)>("crypto_sign_seed_keypair");

typedef _SignNative = Int16 Function(
    Pointer<Uint8> signMsg,
    Pointer<Uint64> smLen,
    Pointer<Uint8> msg,
    Uint64 msgLen,
    Pointer<Uint8> sKey);

typedef _SignDart = int Function(Pointer<Uint8> signMsg, Pointer<Uint64> smLen,
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> sKey);

final sign = libsodium.lookupFunction<_SignNative, _SignDart>("crypto_sign");

typedef _SignOpenNative = Int16 Function(
    Pointer<Uint8> msg,
    Pointer<Uint64> msgLen,
    Pointer<Uint8> signMsg,
    Uint64 smLen,
    Pointer<Uint8> pKey);

typedef _SignOpenDart = int Function(Pointer<Uint8> msg, Pointer<Uint64> msgLen,
    Pointer<Uint8> signMsg, int smLen, Pointer<Uint8> pKey);

final signOpen = libsodium
    .lookupFunction<_SignOpenNative, _SignOpenDart>("crypto_sign_open");
