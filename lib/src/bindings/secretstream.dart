import 'dart:ffi';
import 'sodium.dart';

final keyGen = sodium.lookupFunction<
    Void Function(Pointer<Uint8> key),
    void Function(
        Pointer<Uint8> key)>("crypto_secretstream_xchacha20poly1305_keygen");

class Tag {
  Tag(DynamicLibrary sodium)
      : message = sodium.lookupFunction<Uint8 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_tag_message')(),
        finish = sodium.lookupFunction<Uint8 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_tag_final')(),
        push = sodium.lookupFunction<Uint8 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_tag_push')(),
        rekey = sodium.lookupFunction<Uint8 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_tag_rekey')();
  final int message;
  final int finish;
  final int push;
  final int rekey;
}

typedef SecretStreamInitPushPullNative = Int8 Function(
    Pointer<Uint8> state, Pointer<Uint8> header, Pointer<Uint8> key);
typedef SecretStreamInitPushPullDart = int Function(
    Pointer<Uint8> state, Pointer<Uint8> header, Pointer<Uint8> key);

typedef SecretStreamPushNative = Int8 Function(
    Pointer<Uint8> state,
    Pointer<Uint8> ctext,
    Pointer<Uint64> clen,
    Pointer<Uint8> msg,
    Uint64 mlen,
    Pointer<Uint8> adData,
    Uint64 adlen,
    Pointer<Uint8> tag);
typedef SecretStreamPushDart = int Function(
    Pointer<Uint8> state,
    Pointer<Uint8> ctext,
    Pointer<Uint64> clen,
    Pointer<Uint8> msg,
    int mlen,
    Pointer<Uint8> adData,
    int adlen,
    Pointer<Uint8> tag);

typedef SecretStreamPullNative = Int8 Function(
    Pointer<Uint8> state,
    Pointer<Uint8> msg,
    Pointer<Uint64> msglen,
    Pointer<Uint8> tag,
    Pointer<Uint8> ctext,
    Uint64 clen,
    Pointer<Uint8> adData,
    Uint64 adlen);
typedef SecretStreamPullDart = int Function(
    Pointer<Uint8> state,
    Pointer<Uint8> msg,
    Pointer<Uint64> msglen,
    Pointer<Uint8> tag,
    Pointer<Uint8> ctext,
    int clen,
    Pointer<Uint8> adData,
    int adlen);

class SecretStream {
  SecretStream(DynamicLibrary sodium)
      : keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_keybytes')(),
        stateBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_statebytes')(),
        headerBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
            'crypto_secretstream_xchacha20poly1305_headerbytes')(),
        messageBytesMax =
            sodium.lookupFunction<Uint64 Function(), int Function()>(
                'crypto_secretstream_xchacha20poly1305_messagebytes_max')(),
        keygen = sodium
            .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>(
                'crypto_secretstream_xchacha20poly1305_keygen')
            .asFunction(),
        initPush = sodium
            .lookup<NativeFunction<SecretStreamInitPushPullNative>>(
                'crypto_secretstream_xchacha20poly1305_init_push')
            .asFunction(),
        initPull = sodium
            .lookup<NativeFunction<SecretStreamInitPushPullNative>>(
                'crypto_secretstream_xchacha20poly1305_init_pull')
            .asFunction(),
        push = sodium
            .lookup<NativeFunction<SecretStreamPushNative>>(
                'crypto_secretstream_xchacha20poly1305_push')
            .asFunction(),
        pull = sodium
            .lookup<NativeFunction<SecretStreamPullNative>>(
                'crypto_secretstream_xchacha20poly1305_pull')
            .asFunction(),
        rekey = sodium
            .lookup<NativeFunction<Void Function(Pointer<Uint8> state)>>(
                'crypto_secretstream_xchacha20poly1305_rekey')
            .asFunction();

  final int keyBytes;
  final int stateBytes;
  final int headerBytes;
  final int messageBytesMax;
  final void Function(Pointer<Uint8> key) keygen;
  final SecretStreamInitPushPullDart initPush;
  final SecretStreamPushDart push;
  final SecretStreamInitPushPullDart initPull;
  final SecretStreamPullDart pull;
  final void Function(Pointer<Uint8> state) rekey;
  final tag = Tag(sodium);
}
