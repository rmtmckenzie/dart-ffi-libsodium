import 'dart:ffi';
import 'dart:convert';
import 'dart:typed_data';

Pointer<Uint8> StringToCstr(String str) {
  final buf = utf8.encode(str);
  final Pointer<Uint8> ptr = allocate(count: str.length);
  for (var i = 0; i < str.length; i++) {
    ptr.elementAt(i).store(buf[i]);
  }
  return ptr;
}

String CstrToString(Pointer<Uint8> ptr, int length) {
  final buf = Uint8List(length);
  for (var i = 0; i < length; i++) {
    buf[i] = ptr.elementAt(i).load();
  }
  return utf8.decode(buf);
}
