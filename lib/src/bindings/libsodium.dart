import 'dart:ffi';

import 'random.dart';

class Libsodium {
  Libsodium(DynamicLibrary sodium)
      : init = sodium
            .lookup<NativeFunction<Int8 Function()>>('sodium_init')
            .asFunction(),
        versionString = sodium.lookupFunction<Pointer<Uint8> Function(),
            Pointer<Uint8> Function()>('sodium_version_string')(),
        randomBytes = RandomBytes(sodium);

  factory Libsodium.open(String name) {
    final lib = DynamicLibrary.open(name);
    return Libsodium(lib);
  }

  final int Function() init;
  final Pointer<Uint8> versionString;
  final RandomBytes randomBytes;
}
