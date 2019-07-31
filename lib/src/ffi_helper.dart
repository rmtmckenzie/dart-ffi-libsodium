import 'dart:ffi';
import 'dart:convert';
import 'dart:typed_data';

Pointer<Int8> StringToCstr(String str) {
  final buf = ascii.encode(str);
  final Pointer<Int8> ptr = allocate(count: str.length + 1);
  for (var i = 0; i < str.length; i++) {
    ptr.elementAt(i).store(buf[i]);
  }
  ptr.elementAt(str.length).store(0);
  return ptr;
}

String CstrToString(Pointer<Int8> ptr, int length) {
  final buf = Int8List(length);
  for (var i = 0; i < length; i++) {
    int char = ptr.elementAt(i).load();
    if (char == 0) {
      break;
    }
    buf[i] = char;
  }
  return ascii.decode(buf);
}

Pointer<Uint8> BufferToUnsignedChar(Uint8List buf) {
  final Pointer<Uint8> ptr = allocate(count: buf.length);
  for (var i = 0; i < buf.length; i++) {
    ptr.elementAt(i).store(buf[i]);
  }
  return ptr;
}

Uint8List UnsignedCharToBuffer(Pointer<Uint8> ptr, int length) {
  final buf = Uint8List(length);
  for (var i = 0; i < length; i++) {
    buf[i] = ptr.elementAt(i).load();
  }
  return buf;
}
