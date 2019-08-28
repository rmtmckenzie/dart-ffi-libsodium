import 'dart:ffi';
import 'dart:typed_data';

/// Allocates heap memory with the length of [buf] and fills it with its content.
/// A pointer to the first char gets returned.
/// The resulting char-array is fixed length and not null terminated.
Pointer<Uint8> BufferToUnsignedChar(Uint8List buf) {
  if (buf.isEmpty) {
    final Pointer<Uint8> ptr = allocate();
    ptr.elementAt(0).store(0);
    return ptr;
  }
  final Pointer<Uint8> ptr = allocate(count: buf.length);
  for (var i = 0; i < buf.length; i++) {
    ptr.elementAt(i).store(buf[i]);
  }
  return ptr;
}

/// Returns a buffer with the content of heap memory.
/// The buffer is [length] long and reading from heap begins at [ptr].
/// Reading from heap is not null terminated. If [length] is too long information
/// could be leaked into the application.
Uint8List UnsignedCharToBuffer(Pointer<Uint8> ptr, int length) {
  final buf = Uint8List(length);
  for (var i = 0; i < length; i++) {
    buf[i] = ptr.elementAt(i).load();
  }
  return buf;
}
