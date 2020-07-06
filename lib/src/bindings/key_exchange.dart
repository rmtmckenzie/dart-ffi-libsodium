import 'dart:ffi';

import 'libsodium.dart';

typedef KeyPairNative = Int16 Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey);
typedef KeyPairDart = int Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey);

typedef SeedKeyPairNative = Int16 Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey, Pointer<Uint8> seed);
typedef SeedKeyPairDart = int Function(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey, Pointer<Uint8> seed);

typedef ClientSessionKeysNative = Int16 Function(Pointer<Uint8> receive, Pointer<Uint8> to, Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> serverPk);
typedef ClientSessionKeysDart = int Function(Pointer<Uint8> receive, Pointer<Uint8> to, Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> serverPk);

typedef ServerSessionKeysNative = Int16 Function(Pointer<Uint8> receive, Pointer<Uint8> to, Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> clientPk);
typedef ServerSessionKeysDart = int Function(Pointer<Uint8> receive, Pointer<Uint8> to, Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> clientPk);

class KeyExchange {
  factory KeyExchange([LibSodium libSodium]) {
    return KeyExchange._((libSodium ?? LibSodium()).sodium);
  }

  KeyExchange._(DynamicLibrary sodium)
      : publicKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_kx_publickeybytes')(),
        secretKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_kx_secretkeybytes')(),
        seedBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_kx_seedbytes')(),
        sessionKeyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('crypto_kx_sessionkeybytes')(),
        keyPair = sodium.lookup<NativeFunction<KeyPairNative>>('crypto_kx_keypair').asFunction(),
        seedKeyPair = sodium.lookup<NativeFunction<SeedKeyPairNative>>('crypto_kx_seed_keypair').asFunction(),
        clientSessionKeys = sodium.lookup<NativeFunction<ClientSessionKeysNative>>('crypto_kx_client_session_keys').asFunction(),
        serverSessionKeys = sodium.lookup<NativeFunction<ServerSessionKeysNative>>('crypto_kx_server_session_keys').asFunction();

  final int publicKeyBytes;
  final int secretKeyBytes;
  final int seedBytes;
  final int sessionKeyBytes;

  final KeyPairDart keyPair;
  final SeedKeyPairDart seedKeyPair;
  final ClientSessionKeysDart clientSessionKeys;
  final ServerSessionKeysDart serverSessionKeys;
}
