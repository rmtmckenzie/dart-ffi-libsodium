import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import './dart_sodium_base.dart';
import 'dart:ffi';

typedef _SecretBoxEasyNative = Int16 Function(
    Pointer<Uint8> cyphertext,
    Pointer<Uint8> msg,
    Uint64 msglen,
    Pointer<Uint8> nonce,
    Pointer<Uint8> key);
typedef _SecretBoxEasyDart = int Function(Pointer<Uint8> cyphertext,
    Pointer<Uint8> msg, int msglen, Pointer<Uint8> nonce, Pointer<Uint8> key);
final _secretBoxEasy =
    libsodium.lookupFunction<_SecretBoxEasyNative, _SecretBoxEasyDart>(
        "crypto_secretbox_easy");
final _KEYBYTES = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_keybytes")();
final _NONCEBYTES = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_noncebytes")();
final _MACBYTES = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretbox_macbytes")();

Uint8List secretBoxEasy(Uint8List msg, Uint8List nonce, Uint8List key) {
  if (nonce.length != _NONCEBYTES) {
    throw ArgumentError(
        "The provided nonce hasn't the expected length $_NONCEBYTES: ${nonce.length}");
  }
  if (key.length != _KEYBYTES) {
    throw ArgumentError(
        "The provided key hasn't the expected length $_KEYBYTES: ${key.length}");
  }
  Pointer<Uint8> cypherText;
  Pointer<Uint8> msgPtr;
  Pointer<Uint8> noncePtr;
  Pointer<Uint8> keyPtr;
  try {
    final cypherTextLen = _MACBYTES + msg.length;
    cypherText = allocate(count: cypherTextLen);
    msgPtr = BufferToUnsignedChar(msg);
    noncePtr = BufferToUnsignedChar(nonce);
    keyPtr = BufferToUnsignedChar(key);
    final secretBoxResult =
        _secretBoxEasy(cypherText, msgPtr, msg.length, noncePtr, keyPtr);
    if (secretBoxResult == -1) {
      throw Exception("dart_sodium secretBoxEasy failed: $secretBoxResult");
    }
    return UnsignedCharToBuffer(cypherText, cypherTextLen);
  } finally {
    cypherText?.free();
    msgPtr?.free();
    noncePtr?.free();
    keyPtr?.free();
  }
}