import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

typedef _EasyNative = Int16 Function(
    CString cyphertext, CString msg, Uint64 msglen, CString nonce, CString key);
typedef _EasyDart = int Function(
    CString cyphertext, CString msg, int msglen, CString nonce, CString key);
final easy =
    libsodium.lookupFunction<_EasyNative, _EasyDart>("crypto_secretbox_easy");

typedef _OpenEasyNative = Int16 Function(CString msg, CString cypherText,
    Uint64 cypherTextLen, CString nonce, CString key);
typedef _OpenEasyDart = int Function(CString msg, CString cypherText,
    int cypherTextLen, CString nonce, CString key);
final openEasy = libsodium.lookupFunction<_OpenEasyNative, _OpenEasyDart>(
    "crypto_secretbox_open_easy");

final macBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_macbytes")();

/// Required length of [key]
final keyBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_keybytes")();

/// Required length of [nonce]
final nonceBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_noncebytes")();

final keygen =
    libsodium.lookupFunction<Void Function(CString), void Function(CString)>(
        "crypto_secretbox_keygen");
