import 'dart:ffi';

import 'libsodium.dart';

typedef AuthNative = Int16 Function(Pointer<Uint8> out, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef AuthDart = int Function(Pointer<Uint8> out, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);

typedef AuthVerifyDart = int Function(Pointer<Uint8> tag, Pointer<Uint8> input, int inlen, Pointer<Uint8> key);
typedef AuthVerifyNative = Int8 Function(Pointer<Uint8> tag, Pointer<Uint8> input, Uint64 inlen, Pointer<Uint8> key);

class Authentication {
  factory Authentication([LibSodium libSodium]) {
    return Authentication._((libSodium ?? LibSodium()).sodium);
  }

  Authentication._(DynamicLibrary sodium)
      : keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_auth_keybytes')(),
        authBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_auth_bytes')(),
        auth = sodium.lookup<NativeFunction<AuthNative>>('crypto_auth').asFunction(),
        verify = sodium.lookup<NativeFunction<AuthVerifyNative>>('crypto_auth_verify').asFunction(),
        keyGen = sodium.lookup<NativeFunction<Void Function(Pointer<Uint8>)>>('crypto_auth_keygen').asFunction();

  final int authBytes;
  final int keyBytes;
  final AuthDart auth;
  final AuthVerifyDart verify;
  void Function(Pointer<Uint8> key) keyGen;
}
