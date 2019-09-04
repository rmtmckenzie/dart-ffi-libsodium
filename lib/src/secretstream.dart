import 'dart:ffi';
import 'dart:typed_data';
import 'ffi_helper.dart';

import 'bindings/secretstream.dart' as bindings;

/// Encrypts chunks of a stream
class StreamEncryptor {
  /// Generates a a key for [StreamEncryptor]
  static Uint8List keyGen() {
    final Pointer<Uint8> keyPtr = allocate(count: bindings.keyBytes);
    try {
      bindings.keyGen(keyPtr);
      return CStringToBuffer(keyPtr, bindings.keyBytes);
    } finally {
      keyPtr.free();
    }
  }

  /// Required length of [key]
  static final keyBytes = bindings.keyBytes;

  final Pointer<Uint8> _key;
  final Pointer<Uint8> _header;
  final Pointer<bindings.State> _state;

  /// Header needed for [StreamDecryptor]
  Uint8List get header => CStringToBuffer(_header, bindings.headerBytes);

  StreamEncryptor(Uint8List key)
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

  /// Push new [data] into the stream and get back the encrypted chunk.
  /// You can also add [additionalData] (for example metadata).
  /// There are several [Tag]s to convey information about the status of the stream.
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

  /// Closes the StreamEncryptor
  void close() {
    _key.free();
    _header.free();
    _state.free();
  }
}

/// Possible tags for [StreamEncryptor.push]
/// - [message] is the default and simply means that more messages are coming after this one.
/// - [push] indicates that this message marks the end of a set of messages (for ecample a JSON-stream),
/// but not of the stream itself.
/// - [rekey] means that a new secret key will be derived.
/// - [finish] marks the end of the stream
enum Tag { message, push, rekey, finish }

class PullData {
  final Uint8List decryptedChunk, additionalData;
  final Tag tag;
  const PullData._(this.decryptedChunk, this.additionalData, this.tag);
}

/// Decrypts chunks of a secretstream encrypted by [StreamEncryptor]
class StreamDecryptor {
  final Pointer<Uint8> _key;
  final Pointer<Uint8> _header;
  final Pointer<bindings.State> _state;

  StreamDecryptor(Uint8List key, Uint8List header)
      : _key = BufferToCString(key),
        _header = BufferToCString(header),
        _state = allocate(count: bindings.stateBytes) {
    if (key.length != bindings.keyBytes) {
      close();
      throw Exception("Key hasn't expected length");
    }
    assert(
        header.length == bindings.headerBytes, "Header hasn't expected length");
    int initResult = bindings.initPull(_state, _header, _key);
    if (initResult != 0) {
      close();
      throw Exception("SecretBox init failed. Header seems to be invalid");
    }
  }

  /// Pulls data out of the stream.
  /// [adLen] is the length of [additionalData] provided to [StreamEncryptor.push].
  PullData pull(Uint8List ciphertext, {int adLen = 0}) {
    final dataLen = ciphertext.length - bindings.aBytes;
    final dataPtr = allocate<Uint8>(count: dataLen);
    final cPtr = BufferToCString(ciphertext);
    final tagPtr = allocate<Uint8>();
    final Pointer<Uint8> adPtr =
        adLen == 0 ? fromAddress(0) : allocate(count: adLen);
    try {
      int pushResult = bindings.pull(
          _state, dataPtr, null, tagPtr, cPtr, ciphertext.length, adPtr, adLen);
      if (pushResult != 0) {
        throw Exception("SecretBox pull failed");
      }
      final chunk = CStringToBuffer(dataPtr, dataLen);
      final adData = CStringToBuffer(adPtr, 0);
      final tag = tagPtr.load<int>();
      return PullData._(chunk, adData, Tag.values[tag]);
    } finally {
      dataPtr.free();
      adPtr.free();
      tagPtr.free();
      cPtr.free();
    }
  }

  /// Closes the StreamDecryptor
  void close() {
    _key.free();
    _header.free();
    _state.free();
  }
}
