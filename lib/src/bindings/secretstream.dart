import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:dart_sodium/random.dart';

import '../ffi_helper.dart';

import '../dart_sodium_base.dart';

final secretBoxkeyGen = libsodium.lookupFunction<Void Function(CString key),
    void Function(CString key)>("crypto_secretstream_xchacha20poly1305_keygen");

abstract class Tag {
  static final message =
      libsodium.lookupFunction<Uint8 Function(), int Function()>(
          "crypto_secretstream_xchacha20poly1305_tag_message")();
  static final finish =
      libsodium.lookupFunction<Uint8 Function(), int Function()>(
          "crypto_secretstream_xchacha20poly1305_tag_final")();
  static final push =
      libsodium.lookupFunction<Uint8 Function(), int Function()>(
          "crypto_secretstream_xchacha20poly1305_tag_push")();
  static final rekey =
      libsodium.lookupFunction<Uint8 Function(), int Function()>(
          "crypto_secretstream_xchacha20poly1305_tag_rekey")();
}

final initPush = libsodium.lookupFunction<
    Int16 Function(Pointer<State> state, CString header, CString key),
    int Function(Pointer<State> state, CString header,
        CString key)>("crypto_secretstream_xchacha20poly1305_init_push");

typedef _PushNative = Int16 Function(
    Pointer<State> state,
    CString ciphertext,
    Pointer<Uint64> clen,
    CString msg,
    Uint64 mlen,
    CString adData,
    Uint64 adlen,
    Uint8 tag);
typedef _PushDart = int Function(
    Pointer<State> state,
    CString ciphertext,
    Pointer<Uint64> clen,
    CString msg,
    int mlen,
    CString adData,
    int adlen,
    int tag);

final push = libsodium.lookupFunction<_PushNative, _PushDart>(
    "crypto_secretstream_xchacha20poly1305_push");

typedef _PullNative = Int16 Function(
    Pointer<State> state,
    CString msg,
    Pointer<Uint64> msglen,
    CString tag,
    CString ctxt,
    Uint64 clen,
    CString addData,
    Uint64 adlen);

typedef _PullDart = int Function(
    Pointer<State> state,
    CString msg,
    Pointer<Uint64> msglen,
    CString tag,
    CString ctxt,
    int clen,
    CString addData,
    int adlen);
final pull = libsodium.lookupFunction<_PullNative, _PullDart>(
    "crypto_secretstream_xchacha20poly1305_pull");

final initPull = libsodium.lookupFunction<
    Int16 Function(Pointer<State> state, CString header, CString key),
    int Function(Pointer<State> state, CString header,
        CString key)>("crypto_secretstream_xchacha20poly1305_init_pull");

class State extends Pointer<Void> {}

final keyBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_keybytes")();

final aBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_abytes")();

final stateBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_statebytes")();
