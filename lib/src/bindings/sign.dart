import 'dart:ffi';

import '../dart_sodium_base.dart';

final signBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_sign_bytes")();
final publicKeyBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_sign_publickeybytes")();
final secretKeyBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_sign_bytes")();
final keyPair = libsodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk)>("crypto_sign_keypair");
final stateBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_sign_statebytes")();

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

class State extends Pointer<Void> {}

final signInit = libsodium.lookupFunction<Int16 Function(Pointer<State> state),
    int Function(Pointer<State> state)>("crypto_sign_init");
final signUpdated = libsodium.lookupFunction<
    Int16 Function(Pointer<State> state, Pointer<Uint8> msg, Uint64 mLen),
    int Function(Pointer<State> state, Pointer<Uint8> msg,
        Uint64 mLen)>("crypto_sign_update");
final signFinal = libsodium.lookupFunction<
    Int16 Function(Pointer<State> state, Pointer<Uint8> sig, Uint64 sigLen,
        Pointer<Uint8> sk),
    int Function(Pointer<State> state, Pointer<Uint8> sig, Uint64 sigLen,
        Pointer<Uint8> sk)>("crypto_sign_final_create");
final signFinalVerify = libsodium.lookupFunction<
    Int16 Function(Pointer<State> state, Pointer<Uint8> sig, Pointer<Uint8> pk),
    int Function(Pointer<State> state, Pointer<Uint8> sig,
        Pointer<Uint8> pk)>("crypto_sign_final_verify");
