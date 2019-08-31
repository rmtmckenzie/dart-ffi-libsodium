import 'dart:ffi';
import 'dart:typed_data';
import 'package:dart_sodium/src/ffi_helper.dart';

import 'src/bindings/secretstream.dart' as bindings;

export 'src/bindings/secretstream.dart' show keyBytes;

/// generates a a key for [Encryptor]
Uint8List keyGen() {
  final Pointer<Uint8> keyPtr = allocate(count: bindings.keyBytes);
  try {
    bindings.keyGen(keyPtr);
    return CStringToBuffer(keyPtr, bindings.keyBytes);
  } finally {
    keyPtr.free();
  }
}

/// Encrypts chunks of a stream
class Encryptor {
  final Pointer<Uint8> _key;
  final Pointer<Uint8> _header;
  final Pointer<bindings.State> _state;

  /// Header needed for [Decryptor]
  Uint8List get header => CStringToBuffer(_header, bindings.headerBytes);

  Encryptor(Uint8List key)
      : _key = BufferToCString(key),
        _header = allocate(count: bindings.headerBytes),
        _state = allocate(count: bindings.stateBytes) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw Exception("Key hasn't expected length");
    }

    int initResult = bindings.initPush(_state, _header, _key);
    if (initResult != 0) {
      close();
      throw Exception("SecretBox init failed");
    }
  }

  /// Pushe new [data] into the stream and get back the encrypted chunk
  /// You can also add [additionalData] (metadata).
  /// To end the stream set [tag] to [Tag.finish]
  Uint8List push(Uint8List data,
      {Uint8List additionalData, Tag tag = Tag.message}) {
    Pointer<Uint8> adPtr;
    var adLen = 0;
    if (additionalData == null) {
      adPtr = fromAddress(0);
    } else {
      adLen = additionalData.length;
      adPtr = BufferToCString(additionalData);
    }
    final dataPtr = BufferToCString(data);
    final cLen = data.length + bindings.aBytes;
    final cPtr = allocate<Uint8>(count: cLen);
    try {
      int pushResult = bindings.push(
          _state, cPtr, null, dataPtr, data.length, adPtr, adLen, tag.index);
      if (pushResult != 0) {
        throw Exception("SecretBox push failed");
      }
      return CStringToBuffer(cPtr, cLen);
    } finally {
      dataPtr.free();
      adPtr.free();
      cPtr.free();
    }
  }

  /// Closes the Encryptor. Call this method to avoid memory leaks
  void close() {
    _key.free();
    _header.free();
    _state.free();
  }
}

/// Possible tags for [push]
enum Tag { message, push, rekey, finish }

class _PullData {
  final Uint8List decryptedChunk, additionalData;
  final Tag tag;
  const _PullData(this.decryptedChunk, this.additionalData, this.tag);
}

/// Decrypts chunks of a secretstream encrypted by [Encryptor]
class Decryptor {
  final Pointer<Uint8> _key;
  final Pointer<Uint8> _header;
  final Pointer<bindings.State> _state;

  Decryptor(Uint8List key, Uint8List header)
      : _key = BufferToCString(key),
        _header = BufferToCString(header),
        _state = allocate(count: bindings.stateBytes) {
    if (key.length != bindings.keyBytes) {
      _key.free();
      throw Exception("Key hasn't expected length");
    }
    assert(
        header.length == bindings.headerBytes, "Header hasn't expected length");
    int initResult = bindings.initPull(_state, _header, _key);
    if (initResult != 0) {
      close();
      throw Exception("SecretBox init failed");
    }
  }

  /// Pulls data out of the stream
  _PullData pull(Uint8List ciphertext, {int adLen = 0}) {
    final dataLen = ciphertext.length - bindings.aBytes;
    final dataPtr = allocate<Uint8>(count: dataLen);
    final cPtr = BufferToCString(ciphertext);
    final tagPtr = allocate<Uint8>();
    final adPtr = allocate<Uint8>(count: adLen);
    try {
      int pushResult = bindings.pull(
          _state, dataPtr, null, tagPtr, cPtr, ciphertext.length, adPtr, adLen);
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

  /// Closes the Decryptor. Call this method to avoid memory leaks.
  void close() {
    _key.free();
    _header.free();
    _state.free();
  }
}
