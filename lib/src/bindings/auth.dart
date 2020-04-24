import 'sodium.dart';
import 'dart:ffi';

typedef AuthVerifyDart = int Function(
    Pointer<Uint8> tag, Pointer<Uint8> input, int inlen, Pointer<Uint8> key);
typedef AuthVerifyNative = Uint8 Function(
    Pointer<Uint8> tag, Pointer<Uint8> input, Uint64 inlen, Pointer<Uint8> key);

class Authentication {
  Authentication(DynamicLibrary sodium)
      : keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_auth_keybytes")(),
        authBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
            "crypto_auth_bytes")(),
        verify = sodium
            .lookup<NativeFunction<AuthVerifyNative>>('crypto_auth_verify')
            .asFunction(),
        keygen = sodium
            .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>(
                'crypto_auth_keygen')
            .asFunction();

  final int authBytes;
  final int keyBytes;
  AuthVerifyDart verify;
  void Function(Pointer<Uint8> key) keygen;
}
