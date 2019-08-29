import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:dart_sodium/src/ffi_helper.dart';

import 'dart_sodium.dart';
import 'src/bindings/secretstream.dart' as bindings;

class Encrypter {
  static Uint8List keyGen() {
    Pointer<Uint8> keyPtr;
    try {
      keyPtr = allocate(count: bindings.keyBytes);
      bindings.keyGen(keyPtr);
      return CStringToBuffer(keyPtr, bindings.keyBytes);
    } finally {
      keyPtr.free();
    }
  }

  final Pointer<Uint8> _key;
  Pointer<Uint8> _header;
  Pointer<bindings.State> _state;
  Uint8List get header => CStringToBuffer(_header, bindings.headerBytes);

  Encrypter(Uint8List key) : _key = BufferToCString(key) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw Exception("Key hasn't expected length");
    }
    _header = allocate(count: bindings.headerBytes);
    _state = allocate(count: bindings.stateBytes);
    int initResult = bindings.initPush(_state, _header, _key);
    if (initResult != 0) {
      close();
      throw Exception("SecretBox init failed");
    }
  }

  Uint8List push(Uint8List data,
      {Uint8List additionalData, Tag tag = Tag.message}) {
    Pointer<Uint8> dataPtr, adPtr, cPtr;
    try {
      dataPtr = BufferToCString(data);
      final cLen = data.length + bindings.aBytes;
      cPtr = allocate(count: cLen);
      var adLen = 0;
      if (additionalData != null) {
        adLen = additionalData.length;
        adPtr = BufferToCString(additionalData);
      }
      int pushResult = bindings.push(
          _state, cPtr, null, dataPtr, data.length, adPtr, adLen, tag.index);
      if (pushResult != 0) {
        throw Exception("SecretBox push failed");
      }
      return CStringToBuffer(cPtr, cLen);
    } finally {
      dataPtr?.free();
      adPtr?.free();
      cPtr?.free();
    }
  }

  void close() {
    _key.free();
    _header.free();
    _state.free();
  }
}

enum Tag { message, push, rekey, finish }

class _PullData {
  final Uint8List decryptedChunk, additionalData;
  final Tag tag;
  const _PullData(this.decryptedChunk, this.additionalData, this.tag);
}

class Decrypter {
  final Pointer<Uint8> _key;
  Pointer<Uint8> _header;
  Pointer<bindings.State> _state;

  Decrypter(Uint8List key, Uint8List header)
      : _key = BufferToCString(key),
        _header = BufferToCString(header) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw Exception("Key hasn't expected length");
    }
    assert(
        header.length == bindings.headerBytes, "Header hasn't expected length");
    _state = allocate(count: bindings.stateBytes);
    int initResult = bindings.initPull(_state, _header, _key);
    if (initResult != 0) {
      close();
      throw Exception("SecretBox init failed");
    }
  }

  _PullData pull(Uint8List ciphertext) {
    Pointer<Uint8> dataPtr, adPtr, cPtr, tagPtr;
    try {
      final dataLen = ciphertext.length - bindings.aBytes;
      dataPtr = allocate(count: dataLen);
      cPtr = BufferToCString(ciphertext);
      tagPtr = allocate();
      adPtr = allocate();

      int pushResult = bindings.pull(
          _state, dataPtr, null, tagPtr, cPtr, ciphertext.length, adPtr, 0);
      if (pushResult != 0) {
        throw Exception("SecretBox pull failed");
      }
      final chunk = CStringToBuffer(dataPtr, dataLen);
      final adData = CStringToBuffer(adPtr, 0);
      final tag = tagPtr.load<int>();
      return _PullData(chunk, adData, Tag.values[tag]);
    } finally {
      dataPtr.free();
      adPtr.free();
      tagPtr.free();
      cPtr.free();
    }
  }

  void close() {
    _key.free();
    _header.free();
    _state.free();
  }
}
