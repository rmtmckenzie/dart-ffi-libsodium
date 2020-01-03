import 'sodium.dart';
import 'dart:ffi';

typedef _EasyNative = Int16 Function(
    Pointer<Uint8> cyphertext,
    Pointer<Uint8> msg,
    Uint64 msglen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _EasyDart = int Function(Pointer<Uint8> cyphertext, Pointer<Uint8> msg,
    int msglen, Pointer<Uint8> nonce, Pointer<Uint8> key);
final easy =
    sodium.lookupFunction<_EasyNative, _EasyDart>("crypto_secretbox_easy");

typedef _OpenEasyNative = Int16 Function(
    Pointer<Uint8> msg,
    Pointer<Uint8> cypherText,
    Uint64 cypherTextLen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _OpenEasyDart = int Function(
    Pointer<Uint8> msg,
    Pointer<Uint8> cypherText,
    int cypherTextLen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
final openEasy = sodium.lookupFunction<_OpenEasyNative, _OpenEasyDart>(
    "crypto_secretbox_open_easy");

final macBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_macbytes")();

/// Required length of [key]
final keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_keybytes")();

/// Required length of [nonce]
final nonceBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_noncebytes")();

final keyGen = sodium.lookupFunction<Void Function(Pointer<Uint8>),
    void Function(Pointer<Uint8>)>("crypto_secretbox_keygen");
