import 'dart:ffi';

import 'package:dart_sodium/src/bindings/auth.dart';
import 'package:dart_sodium/src/bindings/pwhash.dart';

import 'random.dart';

typedef SodiumMemoryCompareNative = Int8 Function(
    Pointer<Void> a, Pointer<Void> b, IntPtr len);
typedef SodiumMemoryCompareDart = int Function(
    Pointer<Void> a, Pointer<Void> b, int len);

class Libsodium {
  Libsodium(DynamicLibrary sodium)
      : init = sodium
            .lookup<NativeFunction<Int8 Function()>>('sodium_init')
            .asFunction(),
        versionString = sodium.lookupFunction<Pointer<Uint8> Function(),
            Pointer<Uint8> Function()>('sodium_version_string')(),
        randomBytes = RandomBytes(sodium),
        passwordHash = PasswordHash(sodium),
        authentication = Authentication(sodium),
        memoryCompare = sodium
            .lookup<NativeFunction<SodiumMemoryCompareNative>>('sodium_memcmp')
            .asFunction();

  factory Libsodium.open([String name = 'libsodium']) {
    final lib = DynamicLibrary.open(name);
    return Libsodium(lib);
  }

  final int Function() init;
  final Pointer<Uint8> versionString;
  final RandomBytes randomBytes;
  final PasswordHash passwordHash;
  final Authentication authentication;
  final SodiumMemoryCompareDart memoryCompare;
}
