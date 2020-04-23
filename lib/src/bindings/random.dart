import 'dart:ffi';

class RandomBytes {
  RandomBytes(DynamicLibrary sodium) {
    seedBytes = sodium.lookupFunction<Uint64 Function(), int Function()>(
        'randombytes_seedbytes')();
    random = sodium
        .lookup<NativeFunction<Uint32 Function()>>('randombytes_random')
        .asFunction();
    buffer = sodium
        .lookup<NativeFunction<Void Function(Pointer<Void>, IntPtr)>>(
            'randombytes_buffer')
        .asFunction();
    deterministic = sodium
        .lookup<
            NativeFunction<
                Void Function(Pointer<Void>, IntPtr,
                    Pointer<Uint8>)>>('randombytes_buf_deterministic')
        .asFunction();
    close = sodium
        .lookup<NativeFunction<Int8 Function()>>('randombytes_close')
        .asFunction();
    stir = sodium
        .lookup<NativeFunction<Void Function()>>('randombytes_stir')
        .asFunction();
  }

  int seedBytes;
  int Function() random;
  int Function(int upperBound) uniform;
  void Function(Pointer<Void> buf, int size) buffer;
  void Function(Pointer<Void> buf, int size, Pointer<Uint8> seed) deterministic;
  int Function() close;
  void Function() stir;
}
