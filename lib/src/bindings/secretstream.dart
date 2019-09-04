import 'dart:ffi';

import '../dart_sodium_base.dart';

final keyGen = libsodium.lookupFunction<
    Void Function(Pointer<Uint8> key),
    void Function(
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_keygen");

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
    Int16 Function(
        Pointer<State> state, Pointer<Uint8> header, Pointer<Uint8> key),
    int Function(Pointer<State> state, Pointer<Uint8> header,
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_init_push");

typedef _PushNative = Int16 Function(
    Pointer<State> state,
    Pointer<Uint8> ciphertext,
    Pointer<Uint64> clen,
    Pointer<Uint8> msg,
    Uint64 mlen,
    Pointer<Uint8> adData,
    Uint64 adlen,
    Uint8 tag);
typedef _PushDart = int Function(
    Pointer<State> state,
    Pointer<Uint8> ciphertext,
    Pointer<Uint64> clen,
    Pointer<Uint8> msg,
    int mlen,
    Pointer<Uint8> adData,
    int adlen,
    int tag);

final push = libsodium.lookupFunction<_PushNative, _PushDart>(
    "crypto_secretstream_xchacha20poly1305_push");

typedef _PullNative = Int16 Function(
    Pointer<State> state,
    Pointer<Uint8> msg,
    Pointer<Uint64> msglen,
    Pointer<Uint8> tag,
    Pointer<Uint8> ctxt,
    Uint64 clen,
    Pointer<Uint8> addData,
    Uint64 adlen);

typedef _PullDart = int Function(
    Pointer<State> state,
    Pointer<Uint8> msg,
    Pointer<Uint64> msglen,
    Pointer<Uint8> tag,
    Pointer<Uint8> ctxt,
    int clen,
    Pointer<Uint8> addData,
    int adlen);
final pull = libsodium.lookupFunction<_PullNative, _PullDart>(
    "crypto_secretstream_xchacha20poly1305_pull");

final initPull = libsodium.lookupFunction<
    Int16 Function(
        Pointer<State> state, Pointer<Uint8> header, Pointer<Uint8> key),
    int Function(Pointer<State> state, Pointer<Uint8> header,
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_init_pull");

class State extends Pointer<Void> {}

final keyBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_keybytes")();

final aBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_abytes")();

final stateBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_statebytes")();
final headerBytes = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_headerbytes")();
final msgBytesMax = libsodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_messagebytes_max")();
