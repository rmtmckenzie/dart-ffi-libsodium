import 'dart_sodium_base.dart' show libsodium;
import 'dart:typed_data';
import 'dart:ffi';

final _randomBytesBuf = libsodium.lookupFunction<
    Void Function(Pointer<Uint8> buf, Uint64 size),
    void Function(Pointer<Uint8> buf, int size)>("randombytes_buf");

Uint8List randomBytesBuf(int size) {
  Pointer<Uint8> bufptr;
  try {
    bufptr = allocate(count: size);
    _randomBytesBuf(bufptr, size);
    final buf = Uint8List(size);
    for (var i = 0; i < size; i++) {
      buf[i] = bufptr.elementAt(i).load();
    }
    return buf;
  } finally {
    bufptr?.free();
  }
}
