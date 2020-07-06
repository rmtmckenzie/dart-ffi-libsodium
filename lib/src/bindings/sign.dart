import 'dart:ffi';

import 'package:dart_sodium/src/bindings/libsodium.dart';

typedef KeyPairNative = Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef KeyPairDart = int Function(Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef SeedKeyPairNative = Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed);
typedef SeedKeyPairDart = int Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed);

typedef SignNative = Int16 Function(Pointer<Uint8> signMsg, Pointer<Uint64> smLen, Pointer<Uint8> msg, Uint64 msgLen, Pointer<Uint8> sKey);
typedef SignDart = int Function(Pointer<Uint8> signMsg, Pointer<Uint64> smLen, Pointer<Uint8> msg, int msgLen, Pointer<Uint8> sKey);

typedef SignOpenNative = Int16 Function(Pointer<Uint8> msg, Pointer<Uint64> msgLen, Pointer<Uint8> signMsg, Uint64 smLen, Pointer<Uint8> pKey);
typedef SignOpenDart = int Function(Pointer<Uint8> msg, Pointer<Uint64> msgLen, Pointer<Uint8> signMsg, int smLen, Pointer<Uint8> pKey);

typedef SignInitNative = Int16 Function(Pointer<Uint8> state);
typedef SignInitDart = int Function(Pointer<Uint8> state);

typedef SignUpdateNative = Int16 Function(Pointer<Uint8> state, Pointer<Uint8> msg, Uint64 mLen);
typedef SignUpdateDart = int Function(Pointer<Uint8> state, Pointer<Uint8> msg, int mLen);

typedef SignFinalNative = Int16 Function(Pointer<Uint8> state, Pointer<Uint8> sig, Pointer<Uint64> sigLen, Pointer<Uint8> sk);
typedef SignFinalDart = int Function(Pointer<Uint8> state, Pointer<Uint8> sig, Pointer<Uint64> sigLen, Pointer<Uint8> sk);

typedef SignFinalVerifyNative = Int16 Function(Pointer<Uint8> state, Pointer<Uint8> sig, Pointer<Uint8> pk);
typedef SignFinalVerifyDart = int Function(Pointer<Uint8> state, Pointer<Uint8> sig, Pointer<Uint8> pk);

typedef SignDetachedNative = Int64 Function(Pointer<Uint8> sig, Pointer<Uint64> sigLen, Pointer<Uint8> message, Uint64 messageLength, Pointer<Uint8> secretKey);
typedef SignDetachedDart = int Function(Pointer<Uint8> sig, Pointer<Uint64> sigLen, Pointer<Uint8> message, int messageLength, Pointer<Uint8> secretKey);

typedef SignVerifyDetachedNative = Int64 Function(Pointer<Uint8> sig, Pointer<Uint8> message, Uint64 messageLength, Pointer<Uint8> publicKey);
typedef SignVerifyDetachedDart = int Function(Pointer<Uint8> sig, Pointer<Uint8> message, int messageLength, Pointer<Uint8> publicKey);


class Sign {
  factory Sign([LibSodium libSodium]) {
    return Sign._((libSodium ?? LibSodium()).sodium);
  }

  Sign._(DynamicLibrary sodium)
      : signBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_sign_bytes')(),
        publicKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_sign_publickeybytes')(),
        secretKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_sign_secretkeybytes')(),
        stateBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_sign_statebytes')(),
        seedBytes = sodium.lookupFunction<Int32 Function(), int Function()>('crypto_sign_seedbytes')(),
        keyPair = sodium.lookup<NativeFunction<KeyPairNative>>('crypto_sign_keypair').asFunction(),
        seedKeyPair = sodium.lookup<NativeFunction<SeedKeyPairNative>>('crypto_sign_seed_keypair').asFunction(),
        sign = sodium.lookup<NativeFunction<SignNative>>('crypto_sign').asFunction(),
        signOpen = sodium.lookup<NativeFunction<SignOpenNative>>('crypto_sign_open').asFunction(),
        signInit = sodium.lookup<NativeFunction<SignInitNative>>('crypto_sign_init').asFunction(),
        signUpdate = sodium.lookup<NativeFunction<SignUpdateNative>>('crypto_sign_update').asFunction(),
        signFinal = sodium.lookup<NativeFunction<SignFinalNative>>('crypto_sign_final_create').asFunction(),
        signFinalVerify = sodium.lookup<NativeFunction<SignFinalVerifyNative>>('crypto_sign_final_verify').asFunction(),
        signDetached = sodium.lookup<NativeFunction<SignDetachedNative>>('crypto_sign_detached').asFunction(),
        signVerifyDetached = sodium.lookup<NativeFunction<SignVerifyDetachedNative>>('crypto_sign_verify_detached').asFunction();

  final int signBytes;
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int stateBytes;
  final int seedBytes;

  final KeyPairDart keyPair;
  final SeedKeyPairDart seedKeyPair;
  final SignDart sign;
  final SignOpenDart signOpen;
  final SignInitDart signInit;
  final SignUpdateDart signUpdate;
  final SignFinalDart signFinal;
  final SignFinalVerifyDart signFinalVerify;
  final SignDetachedDart signDetached;
  final SignVerifyDetachedDart signVerifyDetached;
}
