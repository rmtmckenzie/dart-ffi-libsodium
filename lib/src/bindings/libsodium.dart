import 'dart:ffi';

import 'dart:io';

typedef SodiumMemoryCompareNative = Int8 Function(Pointer<Void> a, Pointer<Void> b, IntPtr len);
typedef SodiumMemoryCompareDart = int Function(Pointer<Void> a, Pointer<Void> b, int len);

class LibSodium {
  static LibSodium _instance;

  static final String defaultLibName = Platform.isMacOS ? 'libsodium.dylib' : 'libsodium';

  LibSodium._(this.sodium)
      : init = sodium.lookup<NativeFunction<Int8 Function()>>('sodium_init').asFunction(),
        versionString = sodium.lookupFunction<Pointer<Uint8> Function(), Pointer<Uint8> Function()>('sodium_version_string')(),
        memoryCompare = sodium.lookup<NativeFunction<SodiumMemoryCompareNative>>('sodium_memcmp').asFunction();

  factory LibSodium() {
    _instance ??= LibSodium.open();
    return _instance;
  }

  factory LibSodium.open([String name]) {
    final lib = DynamicLibrary.open(name ?? defaultLibName);
    return LibSodium._(lib);
  }

  final int Function() init;
  final Pointer<Uint8> versionString;
  final SodiumMemoryCompareDart memoryCompare;
  final DynamicLibrary sodium;
}
