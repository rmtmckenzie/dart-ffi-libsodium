import 'dart:ffi';
import 'sodium.dart';

final keyGen = sodium.lookupFunction<
    Void Function(Pointer<Uint8> key),
    void Function(
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_keygen");

abstract class Tag {
  static final message =
      sodium.lookupFunction<Uint8 Function(), int Function()>(
          "crypto_secretstream_xchacha20poly1305_tag_message")();
  static final finish = sodium.lookupFunction<Uint8 Function(), int Function()>(
      "crypto_secretstream_xchacha20poly1305_tag_final")();
  static final push = sodium.lookupFunction<Uint8 Function(), int Function()>(
      "crypto_secretstream_xchacha20poly1305_tag_push")();
  static final rekey = sodium.lookupFunction<Uint8 Function(), int Function()>(
      "crypto_secretstream_xchacha20poly1305_tag_rekey")();
}

final initPush = sodium.lookupFunction<
    Int16 Function(
        Pointer<Uint8> state, Pointer<Uint8> header, Pointer<Uint8> key),
    int Function(Pointer<Uint8> state, Pointer<Uint8> header,
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_init_push");

typedef _PushNative = Int16 Function(
    Pointer<Uint8> state,
    Pointer<Uint8> ciphertext,
    Pointer<Uint64> clen,
    Pointer<Uint8> msg,
    Uint64 mlen,
    Pointer<Uint8> adData,
    Uint64 adlen,
    Uint8 tag);
typedef _PushDart = int Function(
    Pointer<Uint8> state,
    Pointer<Uint8> ciphertext,
    Pointer<Uint64> clen,
    Pointer<Uint8> msg,
    int mlen,
    Pointer<Uint8> adData,
    int adlen,
    int tag);

final push = sodium.lookupFunction<_PushNative, _PushDart>(
    "crypto_secretstream_xchacha20poly1305_push");

typedef _PullNative = Int16 Function(
    Pointer<Uint8> state,
    Pointer<Uint8> msg,
    Pointer<Uint64> msglen,
    Pointer<Uint8> tag,
    Pointer<Uint8> ctxt,
    Uint64 clen,
    Pointer<Uint8> addData,
    Uint64 adlen);

typedef _PullDart = int Function(
    Pointer<Uint8> state,
    Pointer<Uint8> msg,
    Pointer<Uint64> msglen,
    Pointer<Uint8> tag,
    Pointer<Uint8> ctxt,
    int clen,
    Pointer<Uint8> addData,
    int adlen);
final pull = sodium.lookupFunction<_PullNative, _PullDart>(
    "crypto_secretstream_xchacha20poly1305_pull");

final initPull = sodium.lookupFunction<
    Int16 Function(
        Pointer<Uint8> state, Pointer<Uint8> header, Pointer<Uint8> key),
    int Function(Pointer<Uint8> state, Pointer<Uint8> header,
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_init_pull");

final rekey = sodium.lookupFunction<
    Void Function(Pointer<Uint8> state),
    void Function(
        Pointer<Uint8> state)>("crypto_secretstream_xchacha20poly1305_rekey");

final keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_keybytes")();

final aBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_abytes")();

final stateBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_statebytes")();
final headerBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_headerbytes")();
final msgBytesMax = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_secretstream_xchacha20poly1305_messagebytes_max")();

final chacha20IetfNonceBytes =
    sodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_stream_chacha20_ietf_noncebytes")();
final chacha20IetfKeyBytes =
    sodium.lookupFunction<Uint64 Function(), int Function()>(
        "crypto_stream_chacha20_ietf_keybytes")();
