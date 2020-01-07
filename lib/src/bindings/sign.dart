import 'dart:ffi';

import 'sodium.dart';

final signBytes = sodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_sign_bytes")();
final publicKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_sign_publickeybytes")();
final secretKeyBytes = sodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_sign_bytes")();
final keyPair = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk)>("crypto_sign_keypair");
final stateBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_sign_statebytes")();

final seedKeyPair = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed),
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

final sign = sodium.lookupFunction<_SignNative, _SignDart>("crypto_sign");

typedef _SignOpenNative = Int16 Function(
    Pointer<Uint8> msg,
    Pointer<Uint64> msgLen,
    Pointer<Uint8> signMsg,
    Uint64 smLen,
    Pointer<Uint8> pKey);

typedef _SignOpenDart = int Function(Pointer<Uint8> msg, Pointer<Uint64> msgLen,
    Pointer<Uint8> signMsg, int smLen, Pointer<Uint8> pKey);

final signOpen =
    sodium.lookupFunction<_SignOpenNative, _SignOpenDart>("crypto_sign_open");

class State extends Struct {}

final signInit = sodium.lookupFunction<Int16 Function(Pointer<Uint8> state),
    int Function(Pointer<Uint8> state)>("crypto_sign_init");
final signUpdate = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> state, Pointer<Uint8> msg, Uint64 mLen),
    int Function(Pointer<Uint8> state, Pointer<Uint8> msg,
        int mLen)>("crypto_sign_update");
final signFinal = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> state, Pointer<Uint8> sig,
        Pointer<Uint64> sigLen, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> state, Pointer<Uint8> sig,
        Pointer<Uint64> sigLen, Pointer<Uint8> sk)>("crypto_sign_final_create");
final signFinalVerify = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> state, Pointer<Uint8> sig, Pointer<Uint8> pk),
    int Function(Pointer<Uint8> state, Pointer<Uint8> sig,
        Pointer<Uint8> pk)>("crypto_sign_final_verify");
