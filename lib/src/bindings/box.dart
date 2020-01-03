import 'dart:ffi';
import 'sodium.dart';

final secretKeyBytes = sodium.lookupFunction<Int64 Function(), int Function()>(
    "crypto_box_secretkeybytes")();
final publicKeyBytes = sodium.lookupFunction<Int64 Function(), int Function()>(
    "crypto_box_publickeybytes")();
final seedBytes = sodium
    .lookupFunction<Int64 Function(), int Function()>("crypto_box_seedbytes")();
final macBytes = sodium
    .lookupFunction<Int64 Function(), int Function()>("crypto_box_macbytes")();
final nonceBytes = sodium.lookupFunction<Int64 Function(), int Function()>(
    "crypto_box_noncebytes")();
final beforeNumerousBytes =
    sodium.lookupFunction<Int64 Function(), int Function()>(
        "crypto_box_beforenmbytes")();

final keyPair = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk)>("crypto_box_keypair");

final seedKeyPair = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk,
        Pointer<Uint8> seed)>("crypto_box_seed_keypair");

final scalarMultBase = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(
        Pointer<Uint8> pk, Pointer<Uint8> sk)>("crypto_scalarmut_base");

typedef _BoxEasyNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);
typedef _BoxEasyDart = int Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> message,
    int mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);

final easy =
    sodium.lookupFunction<_BoxEasyNative, _BoxEasyDart>("crypto_box_easy");

typedef _BoxOpenEasyNative = Int16 Function(
    Pointer<Uint8> message,
    Pointer<Uint8> ciphertext,
    Uint64 clen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);
typedef _BoxOpenEasyDart = int Function(
    Pointer<Uint8> message,
    Pointer<Uint8> ciphertext,
    int clen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);

final openEasy = sodium.lookupFunction<_BoxOpenEasyNative, _BoxOpenEasyDart>(
    "crypto_box_open_easy");

typedef _BoxDetachedNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);

typedef _BoxDetachedyDart = int Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Pointer<Uint8> message,
    int mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);

final detached = sodium.lookupFunction<_BoxDetachedNative, _BoxDetachedyDart>(
    "crypto_box_detached");
typedef _BoxOpenDetachedNative = Int16 Function(
    Pointer<Uint8> message,
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Uint64 clen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);
typedef _BoxOpenDetachedDart = int Function(
    Pointer<Uint8> message,
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    int clen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);

final openDetached =
    sodium.lookupFunction<_BoxOpenDetachedNative, _BoxOpenDetachedDart>(
        "crypto_box_open_detached");
typedef _BoxEasyAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _BoxEasyAfterNmyDart = int Function(Pointer<Uint8> ciphertext,
    Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

final easyAfterNm =
    sodium.lookupFunction<_BoxEasyAfterNmNative, _BoxEasyAfterNmyDart>(
        "crypto_box_easy_afternm");

typedef _BoxOpenEasyAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _BoxOpenEasyAfterNmDart = int Function(Pointer<Uint8> ciphertext,
    Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

final openEasyAfternumerous =
    sodium.lookupFunction<_BoxOpenEasyAfterNmNative, _BoxOpenEasyAfterNmDart>(
        "crypto_box_open_easy_afternm");

final beforeNumerous = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> k, Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> k, Pointer<Uint8> pk,
        Pointer<Uint8> sk)>("crypto_box_beforenm");

typedef _BoxDetachedAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _BoxDetachedAfterNmyDart = int Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Pointer<Uint8> message,
    int mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);

final detachedAfterNm =
    sodium.lookupFunction<_BoxDetachedAfterNmNative, _BoxDetachedAfterNmyDart>(
        "crypto_box_detached_afternm");

typedef _BoxOpenDetachedAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _BoxOpenDetachedAfterNmDart = int Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> mac,
    Pointer<Uint8> message,
    int mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);

final openDetachedAfterNm = sodium.lookupFunction<_BoxOpenDetachedAfterNmNative,
    _BoxOpenDetachedAfterNmDart>("crypto_box_open_detached_afternm");
