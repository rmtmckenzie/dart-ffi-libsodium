import 'dart:ffi';

import 'libsodium.dart';

typedef AeadXChacha20Poly1305IETFEncryptNative = Int8 Function(
  Pointer<Uint8> cipher,
  Pointer<Uint64> cipherLengthOut,
  Pointer<Uint8> message,
  Uint64 msgLen,
  Pointer<Uint8> additionalData,
  Uint64 additionalDataLength,
  Pointer<Uint8> nsec,
  Pointer<Uint8> nonce,
  Pointer<Uint8> key,
);
typedef AeadXChacha20Poly1305IETFEncryptDart = int Function(
  Pointer<Uint8> cipher,
  Pointer<Uint64> cipherLengthOut,
  Pointer<Uint8> message,
  int msgLen,
  Pointer<Uint8> additionalData,
  int additionalDataLength,
  Pointer<Uint8> nsec,
  Pointer<Uint8> nonce,
  Pointer<Uint8> key,
);

typedef AeadXChacha20Poly1305IETFDecryptNative = Int8 Function(
  Pointer<Uint8> message,
  Pointer<Uint64> messageLengthOut,
  Pointer<Uint8> nsec,
  Pointer<Uint8> cipher,
  Uint64 cipherLength,
  Pointer<Uint8> additionalData,
  Uint64 additionalDataLength,
  Pointer<Uint8> nonce,
  Pointer<Uint8> key,
);
typedef AeadXChacha20Poly1305IETFDecryptDart = int Function(
  Pointer<Uint8> message,
  Pointer<Uint64> messageLengthOut,
  Pointer<Uint8> nsec,
  Pointer<Uint8> cipher,
  int cipherLength,
  Pointer<Uint8> additionalData,
  int additionalDataLength,
  Pointer<Uint8> nonce,
  Pointer<Uint8> key,
);

typedef AeadXChacha20Poly1305IETFKeyGenNative = Void Function(Pointer<Uint8> key);
typedef AeadXChacha20Poly1305IETFKeyGenDart = void Function(Pointer<Uint8> key);

class AeadXChacha20Poly1305IETF {
  factory AeadXChacha20Poly1305IETF([LibSodium libSodium]) {
    return AeadXChacha20Poly1305IETF._((libSodium ?? LibSodium()).sodium);
  }

  AeadXChacha20Poly1305IETF._(DynamicLibrary sodium)
      : nonceBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_aead_xchacha20poly1305_ietf_npubbytes')(),
        keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_aead_xchacha20poly1305_ietf_keybytes')(),
        aBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_aead_xchacha20poly1305_ietf_abytes')(),
        encrypt = sodium.lookup<NativeFunction<AeadXChacha20Poly1305IETFEncryptNative>>('crypto_aead_xchacha20poly1305_ietf_encrypt').asFunction(),
        decrypt = sodium.lookup<NativeFunction<AeadXChacha20Poly1305IETFDecryptNative>>('crypto_aead_xchacha20poly1305_ietf_decrypt').asFunction(),
        keyGen = sodium.lookup<NativeFunction<AeadXChacha20Poly1305IETFKeyGenNative>>('crypto_aead_xchacha20poly1305_ietf_keygen').asFunction();

  final int nonceBytes;
  final int keyBytes;
  final int aBytes;
  final AeadXChacha20Poly1305IETFEncryptDart encrypt;
  final AeadXChacha20Poly1305IETFDecryptDart decrypt;
  final AeadXChacha20Poly1305IETFKeyGenDart keyGen;
}
