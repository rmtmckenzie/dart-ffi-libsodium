import 'sodium.dart';
import 'dart:ffi';

final subkeyBytesMin = sodium.lookupFunction<IntPtr Function(), int Function()>(
    'crypto_kdf_bytes_min')();

final subkeyBytesMax = sodium.lookupFunction<IntPtr Function(), int Function()>(
    'crypto_kdf_bytes_max')();
final contextBytes = sodium.lookupFunction<IntPtr Function(), int Function()>(
    'crypto_kdf_contextbytes')();
final keyBytes = sodium
    .lookupFunction<IntPtr Function(), int Function()>('crypto_kdf_keybytes')();

final keyGen = sodium.lookupFunction<Void Function(Pointer<Uint8> key),
    void Function(Pointer<Uint8> key)>('crypto_kdf_keygen');

typedef _DeriveFromKeyNative = Int16 Function(
    Pointer<Uint8> subkey,
    IntPtr subkeyLength,
    Uint64 subkeyId,
    Pointer<Uint8> context,
    Pointer<Uint8> key);
typedef _DeriveFromKeyDart = int Function(Pointer<Uint8> subkey,
    int subkeyLength, int subkeyId, Pointer<Uint8> context, Pointer<Uint8> key);

final deriveFromKey =
    sodium.lookupFunction<_DeriveFromKeyNative, _DeriveFromKeyDart>(
        'crypto_kdf_derive_from_key');

final hchacha20 = sodium.lookupFunction<
    Int16 Function(Pointer<Uint8> out, Pointer<Uint8> input, Pointer<Uint8> key,
        Pointer<Uint8> constant),
    int Function(Pointer<Uint8> out, Pointer<Uint8> input, Pointer<Uint8> key,
        Pointer<Uint8> constant)>('crypto_core_hchacha20');
