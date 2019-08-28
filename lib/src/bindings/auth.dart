import 'dart:typed_data';

import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

final authKeyGen =
    libsodium.lookupFunction<Void Function(CString), void Function(CString)>(
        "crypto_auth_keygen");

final authBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();

typedef _AuthNative = Void Function(
    CString out, CString msg, Uint64 msglen, CString key);
typedef _AuthDart = void Function(
    CString out, CString msg, int msglen, CString key);

final auth = libsodium.lookupFunction<_AuthNative, _AuthDart>("crypto_auth");

typedef _AuthVerifyNative = Int32 Function(
    CString tag, CString msg, Uint64 msglen, CString key);
typedef _AuthVerifyDart = int Function(
    CString tag, CString msg, int msglen, CString key);
final authVerify = libsodium
    .lookupFunction<_AuthVerifyNative, _AuthVerifyDart>("crypto_auth_verify");
