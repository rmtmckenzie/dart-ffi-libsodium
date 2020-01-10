import 'package:ffi_helper/ffi_helper.dart';
import 'package:ffi/ffi.dart';
import 'dart:ffi';
import 'dart:typed_data';
import 'internal_helpers.dart';

import 'bindings/secretstream.dart' as bindings;

class PullData {
  final Tag tag;
  final Uint8List msg;
  const PullData._(this.msg, this.tag);
}

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

class PushStream with Rekey {
  final Uint8List _state;
  Uint8List _header;

  UnmodifiableUint8ListView get state => UnmodifiableUint8ListView(_state);
  UnmodifiableUint8ListView get header => UnmodifiableUint8ListView(_header);

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
  /// [additionalData] will not be encrypted but it will be included in the computation
  /// of the authentication tag.
  /// The [tag] marks the status of the stream (see libsodium documentation).
  /// Throws a [PushStreamException] when pushing [message] into the stream fails.
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
    final statePtr = Uint8Array.fromTypedList(state);

    final result = bindings.push(statePtr.rawPtr, cPtr.rawPtr, nullptr.cast(),
        msgPtr.rawPtr, message.length, adDataPtr, adDataLen, tag.index);
    adDataPtr ?? free(adDataPtr);
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

/// Decrypts all messeges encrypted with [push] with [key].
/// The decryption stream must be initialized with the [header]
/// Throws a [InitStreamException] when initializing the secret stream fails.
Uint8List initPull(Uint8List header, Uint8List key) {
  final keyPtr = Uint8Array.fromTypedList(key);
  final headerPtr = Uint8Array.fromTypedList(header);
  final statePtr = Uint8Array.allocate(count: bindings.stateBytes);

  final result =
      bindings.initPull(statePtr.rawPtr, headerPtr.rawPtr, keyPtr.rawPtr);
  keyPtr.view.fillZero();
  keyPtr.free();
  headerPtr.free();

  final state = Uint8List.fromList(statePtr.view);
  statePtr.view.fillZero();
  statePtr.free();
  if (result != 0) {
    throw InitStreamError();
  }
  return state;
}

/// Pulls a message out of the stream. [additionalData] must be the same given to [push].
/// Throws [PullError] when pulling message out of stream fails.
PullData pull(Uint8List state, Uint8List chunk, {Uint8List additionalData}) {
  var adDataLen = 0;
  Pointer<Uint8> adDataPtr;
  if (additionalData == null) {
    adDataPtr = nullptr.cast();
  } else {
    adDataLen = additionalData.length;
    adDataPtr = Uint8Array.fromTypedList(additionalData).rawPtr;
  }
  final messagePtr = Uint8Array.allocate(count: chunk.length - bindings.aBytes);
  final cPtr = Uint8Array.fromTypedList(chunk);
  final statePtr = Uint8Array.fromTypedList(state);

  final tagPtr = allocate<Uint8>();
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

  state.setAll(0, statePtr.view);
  statePtr.view.fillZero();
  statePtr.free();

  free(adDataPtr);
  final tag = tagPtr.value;
  free(tagPtr);
  if (result != 0) {
    throw PullError();
  }
  return PullData._(Uint8List.fromList(messagePtr.view), Tag.values[tag]);
}
