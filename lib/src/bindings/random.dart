import 'dart:ffi';

import 'libsodium.dart';

class RandomBytes {
  factory RandomBytes([LibSodium libSodium]) {
    return RandomBytes._((libSodium ?? LibSodium()).sodium);
  }

  RandomBytes._(DynamicLibrary sodium)
      : seedBytes = sodium.lookupFunction<Uint64 Function(), int Function()>('randombytes_seedbytes')(),
        random = sodium.lookup<NativeFunction<Uint32 Function()>>('randombytes_random').asFunction(),
        uniform = sodium.lookup<NativeFunction<Uint32 Function(Uint32)>>('randombytes_uniform').asFunction(),
        buffer = sodium.lookup<NativeFunction<Void Function(Pointer<Void>, IntPtr)>>('randombytes_buf').asFunction(),
        deterministic = sodium.lookup<NativeFunction<Void Function(Pointer<Void>, IntPtr, Pointer<Uint8>)>>('randombytes_buf_deterministic').asFunction(),
        close = sodium.lookup<NativeFunction<Int8 Function()>>('randombytes_close').asFunction(),
        stir = sodium.lookup<NativeFunction<Void Function()>>('randombytes_stir').asFunction();

  final int seedBytes;
  final int Function() random;
  final int Function(int upperBound) uniform;
  final void Function(Pointer<Void> buf, int size) buffer;
  final void Function(Pointer<Void> buf, int size, Pointer<Uint8> seed) deterministic;
  final int Function() close;
  final void Function() stir;
}
