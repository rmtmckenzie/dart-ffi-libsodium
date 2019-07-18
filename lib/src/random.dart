import 'dart_sodium_base.dart' show libsodium;
import 'dart:typed_data';
import 'dart:ffi';

final _randomBytesBuf = libsodium.lookupFunction<
    void Function(Pointer<void> buf, Uint64 size),
    void Function(Pointer<void> buf, int size)>("randombytes_buf");

Uint8List randomBytesBuf(int size) {
  final Pointer<void> bufptr = allocate(count: size);
  try {
    _randomBytesBuf(bufptr, size);
    final buf = Uint8List(size);
    for (var i = 0; i < size; i++) {
      buf[i] = bufptr.elementAt(i).cast();
    }
    return buf;
  } finally {
    bufptr.free();
  }
}
