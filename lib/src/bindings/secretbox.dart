import 'dart:ffi';

import 'libsodium.dart';

typedef SecretBoxEasyNative = Int8 Function(Pointer<Uint8> ciphertext, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef SecretBoxEasyDart = int Function(Pointer<Uint8> ciphertext, Pointer<Uint8> msg, int msglen, Pointer<Uint8> nonce, Pointer<Uint8> key);

typedef SecretBoxOpenEasyNative = Int8 Function(Pointer<Uint8> msg, Pointer<Uint8> cypherText, Uint64 cypherTextLen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef SecretBoxOpenEasyDart = int Function(Pointer<Uint8> msg, Pointer<Uint8> cypherText, int cypherTextLen, Pointer<Uint8> nonce, Pointer<Uint8> key);

typedef SecretBoxDetachedNative = Int8 Function(
    Pointer<Uint8> ctext, Pointer<Uint8> mac, Pointer<Uint8> msg, Uint64 mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef SecretBoxDetachedDart = int Function(Pointer<Uint8> ctext, Pointer<Uint8> mac, Pointer<Uint8> msg, int mlen, Pointer<Uint8> nonce, Pointer<Uint8> key);

typedef SecretBoxOpenDetachedNative = Int8 Function(
    Pointer<Uint8> msg, Pointer<Uint8> ctext, Pointer<Uint8> mac, Uint64 clen, Pointer<Uint8> nonce, Pointer<Uint8> key);
typedef SecretBoxOpenDetachedDart = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>);

class SecretBox {
  factory SecretBox([LibSodium libSodium]) {
    return SecretBox._((libSodium ?? LibSodium()).sodium);
  }

  SecretBox._(DynamicLibrary sodium)
      : macBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_secretbox_macbytes')(),
        keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_secretbox_keybytes')(),
        nonceBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_secretbox_noncebytes')(),
        keygen = sodium.lookup<NativeFunction<Void Function(Pointer<Uint8>)>>('crypto_secretbox_keygen').asFunction(),
        easy = sodium.lookup<NativeFunction<SecretBoxEasyNative>>('crypto_secretbox_easy').asFunction(),
        openEasy = sodium.lookup<NativeFunction<SecretBoxEasyNative>>('crypto_secretbox_open_easy').asFunction(),
        detached = sodium.lookup<NativeFunction<SecretBoxDetachedNative>>('crypto_secretbox_detached').asFunction(),
        openDetached = sodium.lookup<NativeFunction<SecretBoxOpenDetachedNative>>('crypto_secretbox_open_detached').asFunction();

  final int macBytes;
  final int keyBytes;
  final int nonceBytes;
  final void Function(Pointer<Uint8> key) keygen;
  final SecretBoxEasyDart easy;
  final SecretBoxOpenEasyDart openEasy;
  final SecretBoxDetachedDart detached;
  final SecretBoxOpenDetachedDart openDetached;
}
