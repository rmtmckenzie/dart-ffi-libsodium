import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

typedef _SecretBoxEasyNative = Int16 Function(
    CString cyphertext, CString msg, Uint64 msglen, CString nonce, CString key);
typedef _SecretBoxEasyDart = int Function(
    CString cyphertext, CString msg, int msglen, CString nonce, CString key);
final secretBoxEasy =
    libsodium.lookupFunction<_SecretBoxEasyNative, _SecretBoxEasyDart>(
        "crypto_secretbox_easy");

typedef _SecretBoxOpenEasyNative = Int16 Function(CString msg,
    CString cypherText, Uint64 cypherTextLen, CString nonce, CString key);
typedef _SecretBoxOpenEasyDart = int Function(CString msg, CString cypherText,
    int cypherTextLen, CString nonce, CString key);
final secretBoxOpenEasy =
    libsodium.lookupFunction<_SecretBoxOpenEasyNative, _SecretBoxOpenEasyDart>(
        "crypto_secretbox_open_easy");

final secretBoxMacBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_secretbox_macbytes")();

/// Required length of [key]
final secretBoxkeyBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_secretbox_keybytes")();

/// Required length of [nonce]
final secretBoxnonceBytes =
    libsodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_secretbox_noncebytes")();

final secretBoxKeygen =
    libsodium.lookupFunction<Void Function(CString), void Function(CString)>(
        "crypto_secretbox_keygen");
