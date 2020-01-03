import 'sodium.dart';
import 'dart:ffi';

final keyGen = sodium.lookupFunction<Void Function(Pointer<Uint8>),
    void Function(Pointer<Uint8>)>("crypto_auth_keygen");

final authBytes = sodium
    .lookupFunction<Uint64 Function(), int Function()>("crypto_auth_bytes")();
final keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    "crypto_auth_keybytes")();

typedef _AuthNative = Int16 Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _AuthDart = int Function(
    Pointer<Uint8> out, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);
final auth = sodium.lookupFunction<_AuthNative, _AuthDart>("crypto_auth");

typedef _VerifyNative = Int16 Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, Uint64 msglen, Pointer<Uint8> key);
typedef _VerifyDart = int Function(
    Pointer<Uint8> tag, Pointer<Uint8> msg, int msglen, Pointer<Uint8> key);
final verify =
    sodium.lookupFunction<_VerifyNative, _VerifyDart>("crypto_auth_verify");
