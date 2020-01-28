import 'sodium.dart';
import 'dart:ffi';

final publicKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'crypto_kx_publickeybytes')();

final secretKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'crypto_kx_secretkeybytes')();

final seedBytes = sodium
    .lookupFunction<Uint64 Function(), int Function()>('crypto_kx_seedbytes')();

final sessionKeyBytes =
    sodium.lookupFunction<Uint64 Function(), int Function()>(
        'crypto_kx_sessionkeybytes')();

final keyPair = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey),
    int Function(Pointer<Uint8> publicKey,
        Pointer<Uint8> secretKey)>('crypto_kx_keypair');

final seedKeyPair = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey,
        Pointer<Uint8> seed),
    int Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey,
        Pointer<Uint8> seed)>('crypto_kx_keypair');

typedef _ClientSessionKeysNative = Int16 Function(
    Pointer<Uint8> receive,
    Pointer<Uint8> to,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk,
    Pointer<Uint8> serverPk);
typedef _ClientSessionKeysDart = int Function(
    Pointer<Uint8> receive,
    Pointer<Uint8> to,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk,
    Pointer<Uint8> serverPk);

final clientSessionKeys =
    sodium.lookupFunction<_ClientSessionKeysNative, _ClientSessionKeysDart>(
        'crypto_kx_client_session_keys');

typedef _ServerSessionKeysNative = Int16 Function(
    Pointer<Uint8> receive,
    Pointer<Uint8> to,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk,
    Pointer<Uint8> clientPk);
typedef _ServerSessionKeysDart = int Function(
    Pointer<Uint8> receive,
    Pointer<Uint8> to,
    Pointer<Uint8> pk,
    Pointer<Uint8> sk,
    Pointer<Uint8> clientPk);

final serverSessionKeys =
    sodium.lookupFunction<_ClientSessionKeysNative, _ClientSessionKeysDart>(
        'crypto_kx_server_session_keys');
