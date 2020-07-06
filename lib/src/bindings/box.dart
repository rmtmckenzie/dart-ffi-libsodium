import 'dart:ffi';

import 'libsodium.dart';

typedef KeyPairNative = Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef KeyPairDart = int Function(Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef SeedKeyPairNative = Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed);
typedef SeedKeyPairDart = int Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed);

typedef ScalarMultBaseNative = Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef ScalarMultBaseDart = int Function(Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef BoxEasyNative = Int16 Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> message, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef EasyDart = int Function(Pointer<Uint8> ciphertext, Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef OpenEasyNative = Int16 Function(
    Pointer<Uint8> message, Pointer<Uint8> ciphertext, Uint64 clen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef OpenEasyDart = int Function(Pointer<Uint8> message, Pointer<Uint8> ciphertext, int clen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef DetachedNative = Int16 Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Pointer<Uint8> message, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef DetachedDart = int Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef OpenDetachedNative = Int16 Function(
    Pointer<Uint8> message, Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Uint64 clen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef OpenDetachedDart = int Function(
    Pointer<Uint8> message, Pointer<Uint8> ciphertext, Pointer<Uint8> mac, int clen, Pointer<Uint8> nonce, Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef EasyAfterNmNative = Int16 Function(Pointer<Uint8> ciphertext, Pointer<Uint8> message, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef EasyAfterNmDart = int Function(Pointer<Uint8> ciphertext, Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

typedef EasyBeforeNmNative = Int16 Function(Pointer<Uint8> k, Pointer<Uint8> pk, Pointer<Uint8> sk);
typedef BeforeNmDart = int Function(Pointer<Uint8> k, Pointer<Uint8> pk, Pointer<Uint8> sk);

typedef OpenEasyAfterNmNative = Int16 Function(Pointer<Uint8> ciphertext, Pointer<Uint8> message, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef OpenEasyAfterNmDart = int Function(Pointer<Uint8> ciphertext, Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

typedef DetachedAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Pointer<Uint8> message, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef DetachedAfterNmDart = int Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

typedef OpenDetachedAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Pointer<Uint8> message, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef OpenDetachedAfterNmDart = int Function(
    Pointer<Uint8> ciphertext, Pointer<Uint8> mac, Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

class Box {
  factory Box([LibSodium libSodium]) {
    return Box._((libSodium ?? LibSodium()).sodium);
  }

  Box._(DynamicLibrary sodium)
      : secretKeyBytes = sodium.lookupFunction<Int64 Function(), int Function()>('crypto_box_secretkeybytes')(),
        publicKeyBytes = sodium.lookupFunction<Int64 Function(), int Function()>('crypto_box_publickeybytes')(),
        seedBytes = sodium.lookupFunction<Int64 Function(), int Function()>('crypto_box_seedbytes')(),
        macBytes = sodium.lookupFunction<Int64 Function(), int Function()>('crypto_box_macbytes')(),
        nonceBytes = sodium.lookupFunction<Int64 Function(), int Function()>('crypto_box_noncebytes')(),
        beforeNumerousBytes = sodium.lookupFunction<Int64 Function(), int Function()>('crypto_box_beforenmbytes')(),
        keyPair = sodium.lookup<NativeFunction<KeyPairNative>>('crypto_box_keypair').asFunction(),
        seedKeyPair = sodium.lookup<NativeFunction<SeedKeyPairNative>>('crypto_box_seed_keypair').asFunction(),
        scalarMultBase = sodium.lookup<NativeFunction<ScalarMultBaseNative>>('crypto_scalarmult_base').asFunction(),
        easy = sodium.lookup<NativeFunction<BoxEasyNative>>('crypto_box_easy').asFunction(),
        openEasy = sodium.lookup<NativeFunction<OpenEasyNative>>('crypto_box_open_easy').asFunction(),
        detached = sodium.lookup<NativeFunction<DetachedNative>>('crypto_box_detached').asFunction(),
        openDetached = sodium.lookup<NativeFunction<OpenDetachedNative>>('crypto_box_open_detached').asFunction(),
        easyAfterNm = sodium.lookup<NativeFunction<EasyAfterNmNative>>('crypto_box_easy_afternm').asFunction(),
        beforeNm = sodium.lookup<NativeFunction<EasyBeforeNmNative>>('crypto_box_beforenm').asFunction(),
        openEasyAfterNm = sodium.lookup<NativeFunction<OpenEasyAfterNmNative>>('crypto_box_open_easy_afternm').asFunction(),
        detachedAfterNm = sodium.lookup<NativeFunction<DetachedAfterNmNative>>('crypto_box_detached_afternm').asFunction(),
        openDetachedAfterNm = sodium.lookup<NativeFunction<OpenDetachedAfterNmNative>>('crypto_box_open_detached_afternm').asFunction();

  final int secretKeyBytes;
  final int publicKeyBytes;
  final int seedBytes;
  final int macBytes;
  final int nonceBytes;
  final int beforeNumerousBytes;

  final KeyPairDart keyPair;
  final SeedKeyPairDart seedKeyPair;
  final ScalarMultBaseDart scalarMultBase;
  final EasyDart easy;
  final OpenEasyDart openEasy;
  final DetachedDart detached;
  final OpenDetachedDart openDetached;
  final EasyAfterNmDart easyAfterNm;
  final BeforeNmDart beforeNm;
  final OpenEasyAfterNmDart openEasyAfterNm;
  final DetachedAfterNmDart detachedAfterNm;
  final OpenDetachedAfterNmDart openDetachedAfterNm;
}
