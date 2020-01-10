import 'package:ffi_helper/ffi_helper.dart';
import 'package:ffi/ffi.dart';
import 'dart:ffi';
import 'dart:typed_data';
import 'internal_helpers.dart';

import 'bindings/secretstream.dart' as bindings;

class PullError extends Error {
  @override
  String toString() {
    return "Pulling from secret stream failed";
  }
}

class InitStreamError extends Error {
  @override
  String toString() {
    return "Initializing secret stream failed";
  }
}

class PushError extends Error {
  @override
  String toString() {
    return "Pushing into secret stream failed";
  }
}

/// Marks the state of the stream (see libsodium documentation)
enum Tag { message, finalize, push, rekey }

mixin Rekey {
  Uint8List get _state;

  /// Generates a new key for the secret stream (see libsodium documentation).
  void rekey() {
    final statePtr = Uint8Array.fromTypedList(_state);
    bindings.rekey(statePtr.rawPtr);
    _state.setAll(0, statePtr.view);
    statePtr.freeZero();
  }
}

/// Encryption stream
class PushStream with Rekey {
  @override
  final Uint8List _state;
  Uint8List _header;

  /// State of the stream. You can save [state] to [resume] at a later point
  /// or send it to another machine / thread to split up the workload.
  UnmodifiableUint8ListView get state => UnmodifiableUint8ListView(_state);

  /// Header of the stream. Required to initialize a [PullStream].
  UnmodifiableUint8ListView get header => UnmodifiableUint8ListView(_header);

  /// Resume the [PushStream] from a saved [state].
  PushStream.resume(this._state, [this._header]);

  factory PushStream(Uint8List key) {
    final keyPtr = Uint8Array.fromTypedList(key);
    final headerPtr = Uint8Array.allocate(count: bindings.headerBytes);
    final statePtr = Uint8Array.allocate(count: bindings.stateBytes);

    final result =
        bindings.initPush(statePtr.rawPtr, headerPtr.rawPtr, keyPtr.rawPtr);
    keyPtr.freeZero();
    headerPtr.free();

    final state = Uint8List.fromList(statePtr.view);
    statePtr.freeZero();

    final header = Uint8List.fromList(headerPtr.view);
    if (result != 0) {
      throw InitStreamError();
    }
    return PushStream.resume(state, header);
  }

  /// Pushes [message] into the stream. [message] cannot be longer than [msgBytesMax] (~256 GB).
  /// [additionalData] will not be encrypted but will be included in the computation
  /// of the authentication tag (see libsodium documentation).
  /// [tag] marks the status of the stream (see libsodium documentation).
  /// Throws [PushError] when pushing [message] into the stream fails.
  Uint8List push(Uint8List message,
      {Uint8List additionalData, Tag tag = Tag.message}) {
    var adDataLen = 0;
    Pointer<Uint8> adDataPtr;
    if (additionalData == null) {
      adDataPtr = nullptr.cast();
    } else {
      adDataLen = additionalData.length;
      adDataPtr = Uint8Array.fromTypedList(additionalData).rawPtr;
    }
    final msgPtr = Uint8Array.fromTypedList(message);
    final cPtr = Uint8Array.allocate(count: message.length + bindings.aBytes);
    final statePtr = Uint8Array.fromTypedList(_state);

    final result = bindings.push(statePtr.rawPtr, cPtr.rawPtr, nullptr.cast(),
        msgPtr.rawPtr, message.length, adDataPtr, adDataLen, tag.index);
    free(adDataPtr);
    msgPtr.free();
    cPtr.free();

    _state.setAll(0, statePtr.view);
    statePtr.freeZero();
    if (result != 0) {
      throw PushError();
    }
    return Uint8List.fromList(cPtr.view);
  }
}

/// Generates a key for a secret stream.
UnmodifiableUint8ListView keyGen() {
  final keyPtr = Uint8Array.allocate(count: bindings.keyBytes);
  bindings.keyGen(keyPtr.rawPtr);
  final key = Uint8List.fromList(keyPtr.view);
  keyPtr.view.fillZero();
  keyPtr.free();
  return UnmodifiableUint8ListView(key);
}

/// Decryption stream
class PullStream with Rekey {
  @override
  final Uint8List _state;

  /// State of the stream. You can save [state] to [resume] at a later point
  /// or send it to another machine / thread to split up the workload.
  UnmodifiableUint8ListView get state => _state;
  Tag _tag;

  /// Status of the stream (see libsodium documentation).
  /// Will be updated with every [pull].
  Tag get tag => _tag;

  /// Resume [PushStream] from a saved [state].
  PullStream.resume(this._state);
  factory PullStream(Uint8List key, Uint8List header) {
    final keyPtr = Uint8Array.fromTypedList(key);
    final headerPtr = Uint8Array.fromTypedList(header);
    final statePtr = Uint8Array.allocate(count: bindings.stateBytes);

    final result =
        bindings.initPull(statePtr.rawPtr, headerPtr.rawPtr, keyPtr.rawPtr);
    keyPtr.freeZero();
    headerPtr.free();

    final state = Uint8List.fromList(statePtr.view);
    statePtr.freeZero();
    if (result != 0) {
      throw InitStreamError();
    }
    return PullStream.resume(state);
  }

  /// Pulls a message out of the stream. [additionalData] must be the same given to [push].
  /// If [readTag] is true [tag] will be updated with the tag of this message; otherwise
  /// [tag] stays null
  /// Throws [PullError] when pulling message out of stream fails.
  Uint8List pull(Uint8List chunk,
      {Uint8List additionalData, bool readTag = false}) {
    var adDataLen = 0;
    Pointer<Uint8> adDataPtr;
    if (additionalData == null) {
      adDataPtr = nullptr.cast();
    } else {
      adDataLen = additionalData.length;
      adDataPtr = Uint8Array.fromTypedList(additionalData).rawPtr;
    }
    final messagePtr =
        Uint8Array.allocate(count: chunk.length - bindings.aBytes);
    final cPtr = Uint8Array.fromTypedList(chunk);
    final statePtr = Uint8Array.fromTypedList(_state);

    final tagPtr = readTag ? allocate<Uint8>() : nullptr.cast<Uint8>();
    final result = bindings.pull(
        statePtr.rawPtr,
        messagePtr.rawPtr,
        nullptr.cast<Uint64>(),
        tagPtr,
        cPtr.rawPtr,
        chunk.length,
        adDataPtr,
        adDataLen);
    messagePtr.free();
    cPtr.free();

    _state.setAll(0, statePtr.view);
    statePtr.freeZero();

    free(adDataPtr);
    _tag = readTag ? Tag.values[tagPtr.value] : null;
    free(tagPtr);
    if (result != 0) {
      throw PullError();
    }

    return Uint8List.fromList(messagePtr.view);
  }
}
