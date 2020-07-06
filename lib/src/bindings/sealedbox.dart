import 'dart:ffi';

import 'libsodium.dart';

typedef SealNative = Int8 Function(Pointer<Uint8> ciphertext, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> publicKey);
typedef SealDart = int Function(Pointer<Uint8> ciphertext, Pointer<Uint8> msg, int msglen, Pointer<Uint8> publicKey);

typedef OpenNative = Int8 Function(Pointer<Uint8> msg, Pointer<Uint8> ciphertext, Uint64 ciphertextlen, Pointer<Uint8> publicKey, Pointer<Uint8> secretKey);
typedef OpenDart = int Function(Pointer<Uint8> msg, Pointer<Uint8> ciphertext, int ciphertextlen, Pointer<Uint8> publicKey, Pointer<Uint8> secretKey);

class SealedBox {
  factory SealedBox([LibSodium libSodium]) {
    return SealedBox._((libSodium ?? LibSodium()).sodium);
  }

  SealedBox._(DynamicLibrary sodium)
      : sealBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_box_sealbytes')(),
        seal = sodium.lookup<NativeFunction<SealNative>>('crypto_box_seal').asFunction(),
        open = sodium.lookup<NativeFunction<OpenNative>>('crypto_box_seal_open').asFunction();

  final int sealBytes;
  final SealDart seal;
  final OpenDart open;
}
