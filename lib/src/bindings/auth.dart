import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

final _authKeyGen =
    libsodium.lookupFunction<Void Function(CString), void Function(CString)>(
        "crypto_auth_keygen");

/// Length of the authentication tag.
final _authBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();

typedef _AuthNative = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthDart = void Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);

final _auth = libsodium.lookupFunction<_AuthNative, _AuthDart>("crypto_auth");

typedef _AuthVerifyNative = Int32 Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthVerifyDart = int Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);
final _authVerify = libsodium
    .lookupFunction<_AuthVerifyNative, _AuthVerifyDart>("crypto_auth_verify");

main(List<String> args) {
  Pointer<CString> ptr = allocate();
  print(ptr);
}
