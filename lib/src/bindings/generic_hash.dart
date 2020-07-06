import 'dart:ffi';

import 'libsodium.dart';

typedef GenericHashNative = Int16 Function(Pointer<Uint8> out, IntPtr outlen, Pointer<Uint8> input, Uint64 inlen, Pointer<Uint8> key, IntPtr keylen);
typedef GenericHashDart = int Function(Pointer<Uint8> out, int outlen, Pointer<Uint8> input, int inlen, Pointer<Uint8> key, int keylen);

typedef InitNative = Int16 Function(Pointer<Uint8> state, Pointer<Uint8> key, IntPtr keylen, IntPtr outlen);
typedef InitDart = int Function(Pointer<Uint8> state, Pointer<Uint8> key, int keylen, int outlen);

typedef UpdateNative = Int16 Function(Pointer<Uint8> state, Pointer<Uint8> input, Uint64 inlen);
typedef UpdateDart = int Function(Pointer<Uint8> state, Pointer<Uint8> input, int inlen);

typedef FinishNative = Int16 Function(Pointer<Uint8> state, Pointer<Uint8> out, Uint64 outlen);
typedef FinishDart = int Function(Pointer<Uint8> state, Pointer<Uint8> out, int outlen);

typedef KeyGenNative = Void Function(Pointer<Uint8> key);
typedef KeyGenDart = void Function(Pointer<Uint8> key);

class GenericHash {
  factory GenericHash([LibSodium libSodium]) {
    return GenericHash._((libSodium ?? LibSodium()).sodium);
  }

  GenericHash._(DynamicLibrary sodium)
      : genericHashBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_bytes')(),
        genericHashBytesMin = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_bytes_min')(),
        genericHashBytesMax = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_bytes_max')(),
        keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_keybytes')(),
        keyBytesMax = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_keybytes_max')(),
        keyBytesMin = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_keybytes_min')(),
        stateBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_generichash_statebytes')(),
        genericHash = sodium.lookup<NativeFunction<GenericHashNative>>('crypto_generichash').asFunction(),
        init = sodium.lookup<NativeFunction<InitNative>>('crypto_generichash_init').asFunction(),
        update = sodium.lookup<NativeFunction<UpdateNative>>('crypto_generichash_update').asFunction(),
        finish = sodium.lookup<NativeFunction<FinishNative>>('crypto_generichash_final').asFunction(),
        keyGen = sodium.lookup<NativeFunction<KeyGenNative>>('crypto_generichash_keygen').asFunction();

  final int genericHashBytes;
  final int genericHashBytesMin;
  final int genericHashBytesMax;
  final int keyBytes;
  final int keyBytesMax;
  final int keyBytesMin;
  final int stateBytes;

  final GenericHashDart genericHash;
  final InitDart init;
  final UpdateDart update;
  final FinishDart finish;
  final KeyGenDart keyGen;
}
