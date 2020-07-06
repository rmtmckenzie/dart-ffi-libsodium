import 'dart:ffi';

import 'package:dart_sodium/src/bindings/libsodium.dart';

class OpsLimit {
  factory OpsLimit([LibSodium libSodium]) {
    return OpsLimit._((libSodium ?? LibSodium()).sodium);
  }

  OpsLimit._(DynamicLibrary sodium)
      : min = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_opslimit_min')(),
        moderate = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_opslimit_moderate')(),
        interactive = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_opslimit_interactive')(),
        sensitive = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_opslimit_sensitive')(),
        max = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_opslimit_max')();

  final int min;
  final int interactive;
  final int moderate;
  final int sensitive;
  final int max;
}

class MemLimit {
  factory MemLimit([LibSodium libSodium]) {
    return MemLimit._((libSodium ?? LibSodium()).sodium);
  }

  MemLimit._(DynamicLibrary sodium)
      : min = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_memlimit_min')(),
        moderate = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_memlimit_moderate')(),
        interactive = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_memlimit_interactive')(),
        sensitive = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_memlimit_sensitive')(),
        max = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_memlimit_max')();

  final int min;
  final int interactive;
  final int moderate;
  final int sensitive;
  final int max;
}

typedef PwhashStorageNative = Int8 Function(Pointer<Uint8> out, Pointer<Uint8> passwd, Uint64 passwdLen, Uint64 opsLimit, IntPtr memlimit);
typedef PwhashStorageDart = int Function(Pointer<Uint8> out, Pointer<Uint8> passwd, int passwdLen, int opsLimit, int memlimit);

typedef PwhashStorageVerifyNative = Int8 Function(Pointer<Uint8> str, Pointer<Uint8> passwd, IntPtr passwdlen);
typedef PwhashStorageVerifyDart = int Function(Pointer<Uint8> str, Pointer<Uint8> passwd, int passwdlen);

typedef PwhashNeedsRehashNative = Int8 Function(Pointer<Uint8> str, Uint64 opsLimit, IntPtr memLimit);
typedef PwhashNeedsRehashDart = int Function(Pointer<Uint8> str, int opsLimit, int memLimit);

typedef PwhashNative = Int8 Function(
    Pointer<Uint8> out, Uint64 outlen, Pointer<Uint8> password, Uint64 pwlen, Pointer<Uint8> salt, Uint64 opslimit, IntPtr memlimit, Int8 alg);
typedef PwhashDart = int Function(Pointer<Uint8> out, int outlen, Pointer<Uint8> password, int pwlen, Pointer<Uint8> salt, int opslimit, int memlimit, int alg);

class PasswordHash {
  factory PasswordHash([LibSodium libSodium]) {
    return PasswordHash._((libSodium ?? LibSodium()).sodium);
  }

  PasswordHash._(DynamicLibrary sodium)
      : opslimit = OpsLimit._(sodium),
        memlimit = MemLimit._(sodium),
        storeBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_strbytes')(),
        passwordMax = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_passwd_max')(),
        passwordMin = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_pwhash_passwd_min')(),
        storage = sodium.lookup<NativeFunction<PwhashStorageNative>>('crypto_pwhash_str').asFunction(),
        verify = sodium.lookup<NativeFunction<PwhashStorageVerifyNative>>('crypto_pwhash_str_verify').asFunction(),
        needsRehash = sodium.lookup<NativeFunction<PwhashNeedsRehashNative>>('crypto_pwhash_str_needs_rehash').asFunction();

  final OpsLimit opslimit;
  final MemLimit memlimit;
  final int storeBytes;
  final int passwordMax;
  final int passwordMin;

  final PwhashStorageDart storage;
  final PwhashStorageVerifyDart verify;
  final PwhashNeedsRehashDart needsRehash;
}
