import 'dart:ffi';
import '../dart_sodium_base.dart';

final secretKeyBytes =
    libsodium.lookupFunction<Int64 Function(), int Function()>(
        "crypto_box_secretkeybytes")();
final publicKeyBytes =
    libsodium.lookupFunction<Int64 Function(), int Function()>(
        "crypto_box_publickeybytes")();
final seedBytes = libsodium
    .lookupFunction<Int64 Function(), int Function()>("crypto_box_seedbytes")();
final macBytes = libsodium
    .lookupFunction<Int64 Function(), int Function()>("crypto_box_macbytes")();
final nonceBytes = libsodium.lookupFunction<Int64 Function(), int Function()>(
    "crypto_box_noncebytes")();
final beforeNmBytes =
    libsodium.lookupFunction<Int64 Function(), int Function()>(
        "crypto_box_beforenmbytes")();

final keyPair = libsodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk)>("crypto_box_keypair");

final seedKeyPair = libsodium.lookupFunction<
    Int16 Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed),
    int Function(Pointer<Uint8> pk, Pointer<Uint8> sk,
        Pointer<Uint8> seed)>("crypto_box_seed_keypair");

final scalarMultBase = libsodium.lookupFunction<
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
    libsodium.lookupFunction<_BoxEasyNative, _BoxEasyDart>("crypto_box_easy");

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

final openEasy = libsodium.lookupFunction<_BoxOpenEasyNative, _BoxOpenEasyDart>(
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

final detached =
    libsodium.lookupFunction<_BoxDetachedNative, _BoxDetachedyDart>(
        "crypto_box_detached");
typedef _BoxOpenDetachedNative = Int16 Function(
    Pointer<Uint8> message,
    Pointer<Uint8> ciphertext,
    Uint64 clen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);
typedef _BoxOpenDetachedDart = int Function(
    Pointer<Uint8> message,
    Pointer<Uint8> ciphertext,
    int clen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk);

final openDetached =
    libsodium.lookupFunction<_BoxOpenDetachedNative, _BoxOpenDetachedDart>(
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
    libsodium.lookupFunction<_BoxEasyAfterNmNative, _BoxEasyAfterNmyDart>(
        "crypto_box_easy_afternm");

typedef _BoxOpenEasyAfterNmNative = Int16 Function(
    Pointer<Uint8> ciphertext,
    Pointer<Uint8> message,
    Uint64 mlen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _BoxOpenEasyAfterNmDart = int Function(Pointer<Uint8> ciphertext,
    Pointer<Uint8> message, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

final openEasyAfterNm = libsodium.lookupFunction<_BoxOpenEasyAfterNmNative,
    _BoxOpenEasyAfterNmDart>("crypto_box_open_easy_afternm");

final beforeNm = libsodium.lookupFunction<
    Int16 Function(Pointer<Uint8> k, Pointer<Uint8> pk, Pointer<Uint8> sk),
    int Function(Pointer<Uint8> k, Pointer<Uint8> pk,
        Pointer<Uint8> sk)>("crypto_box_beforenm");
