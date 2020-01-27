import 'sodium.dart';
import 'dart:ffi';

final genericHashBytes =
    sodium.lookupFunction<Uint64 Function(), int Function()>(
        'crypto_generichash_bytes')();

final genericHashBytesMin =
    sodium.lookupFunction<Uint64 Function(), int Function()>(
        'crypto_generichash_bytes_min')();
final genericHashBytesMax =
    sodium.lookupFunction<Uint64 Function(), int Function()>(
        'crypto_generichash_bytes_max')();

final keyBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'crypto_generichash_keybytes')();
final keyBytesMax = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'crypto_generichash_keybytes_max')();
final keyBytesMin = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'crypto_generichash_keybytes_min')();

final stateBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
    'crypto_generichash_statebytes')();

typedef _GenericHashNative = Int16 Function(Pointer<Uint8> out, IntPtr outlen,
    Pointer<Uint8> input, Uint64 inlen, Pointer<Uint8> key, IntPtr keylen);
typedef _GenericHashDart = int Function(Pointer<Uint8> out, int outlen,
    Pointer<Uint8> input, int inlen, Pointer<Uint8> key, int keylen);

final genericHash = sodium
    .lookupFunction<_GenericHashNative, _GenericHashDart>('crypto_generichash');

typedef _InitNative = Int16 Function(
    Pointer<Uint8> state, Pointer<Uint8> key, IntPtr keylen, IntPtr outlen);
typedef _InitDart = int Function(
    Pointer<Uint8> state, Pointer<Uint8> key, int keylen, int outlen);

final init =
    sodium.lookupFunction<_InitNative, _InitDart>('crypto_generichash_init');

final update = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> state, Pointer<Uint8> input, Uint64 inlen),
    int Function(Pointer<Uint8> state, Pointer<Uint8> input,
        int inlen)>('crypto_generichash_update');

final finish = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> state, Pointer<Uint8> out, Uint64 outlen),
    int Function(Pointer<Uint8> state, Pointer<Uint8> out,
        int outlen)>('crypto_generichash_final');

final keyGen = sodium.lookupFunction<Void Function(Pointer<Uint8> key),
    void Function(Pointer<Uint8> key)>('crypto_generichash_keygen');
