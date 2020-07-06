import 'dart:ffi';

import 'libsodium.dart';

typedef KeyGenNative = Void Function(Pointer<Uint8> key);
typedef KeyGenDart = void Function(Pointer<Uint8> key);

typedef DeriveFromKeyNative = Int16 Function(Pointer<Uint8> subkey, IntPtr subkeyLength, Uint64 subkeyId, Pointer<Uint8> context, Pointer<Uint8> key);
typedef DeriveFromKeyDart = int Function(Pointer<Uint8> subkey, int subkeyLength, int subkeyId, Pointer<Uint8> context, Pointer<Uint8> key);

typedef HChaCha20Native = Int16 Function(Pointer<Uint8> out, Pointer<Uint8> input, Pointer<Uint8> key, Pointer<Uint8> constant);
typedef HChaCha20Dart = int Function(Pointer<Uint8> out, Pointer<Uint8> input, Pointer<Uint8> key, Pointer<Uint8> constant);

class KeyDerivation {
  factory KeyDerivation([LibSodium libSodium]) {
    return KeyDerivation._((libSodium ?? LibSodium()).sodium);
  }

  KeyDerivation._(DynamicLibrary sodium)
      : subkeyBytesMin = sodium.lookupFunction<IntPtr Function(), int Function()>('crypto_kdf_bytes_min')(),
        subkeyBytesMax = sodium.lookupFunction<IntPtr Function(), int Function()>('crypto_kdf_bytes_max')(),
        contextBytes = sodium.lookupFunction<IntPtr Function(), int Function()>('crypto_kdf_contextbytes')(),
        keyBytes = sodium.lookupFunction<IntPtr Function(), int Function()>('crypto_kdf_keybytes')(),
        keyGen = sodium.lookup<NativeFunction<KeyGenNative>>('crypto_kdf_keygen').asFunction(),
        deriveFromKey = sodium.lookup<NativeFunction<DeriveFromKeyNative>>('crypto_kdf_derive_from_key').asFunction(),
        hchacha20 = sodium.lookup<NativeFunction<HChaCha20Native>>('crypto_core_hchacha20').asFunction();

  final int subkeyBytesMin;
  final int subkeyBytesMax;
  final int contextBytes;
  final int keyBytes;

  final KeyGenDart keyGen;
  final DeriveFromKeyDart deriveFromKey;
  final HChaCha20Dart hchacha20;

}
