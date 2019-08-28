import 'package:dart_sodium/src/ffi_helper.dart';

import '../dart_sodium_base.dart';
import 'dart:ffi';

final keyGen =
    libsodium.lookupFunction<Void Function(CString), void Function(CString)>(
        "crypto_auth_keygen");

final authBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();
final keyBytes = libsodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_key")();

typedef _AuthNative = Int16 Function(
    CString out, CString msg, Uint64 msglen, CString key);
typedef _AuthDart = int Function(
    CString out, CString msg, int msglen, CString key);
final auth = libsodium.lookupFunction<_AuthNative, _AuthDart>("crypto_auth");

typedef _VerifyNative = Int16 Function(
    CString tag, CString msg, Uint64 msglen, CString key);
typedef _VerifyDart = int Function(
    CString tag, CString msg, int msglen, CString key);
final verify =
    libsodium.lookupFunction<_VerifyNative, _VerifyDart>("crypto_auth_verify");
