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
