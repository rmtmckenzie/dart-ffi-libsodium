import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi_helper/ffi_helper.dart';

import 'bindings/secretstream.dart' as bindings;
import 'helpers/internal_helpers.dart';

class PullError extends Error {
  @override
  String toString() {
    return 'Pulling from secret stream failed';
  }
}

class InitStreamError extends Error {
  @override
  String toString() {
    return 'Initializing secret stream failed';
  }
}

class PushError extends Error {
  @override
  String toString() {
    return 'Pushing into secret stream failed';
  }
}

/// Marks the state of the stream (see libsodium documentation)
enum Tag { message, finalize, push, rekey }

Map<int, Tag> _tagMap;

extension TagNative on Tag {
  // ignore: missing_return
  int toNative([bindings.SecretStream binding]) {
    final _binding = binding ?? bindings.SecretStream();
    final _tagBinding = _binding.tag;

    switch (this) {
      case Tag.message:
        return _tagBinding.message;
        break;
      case Tag.finalize:
        return _tagBinding.finish;
        break;
      case Tag.push:
        return _tagBinding.push;
        break;
      case Tag.rekey:
        return _tagBinding.rekey;
        break;
    }
  }

  static Tag fromNative(int value, [bindings.SecretStream binding]) {
    final _binding = binding ?? bindings.SecretStream();
    final _tagBinding = _binding.tag;

    final map = _tagMap ??
        {
          _tagBinding.message: Tag.message,
          _tagBinding.push: Tag.push,
          _tagBinding.rekey: Tag.rekey,
          _tagBinding.finish: Tag.finalize,
        };

    if (map.containsKey(value)) {
      return map[value];
    } else {
      throw ArgumentError('Tag $value not supported');
    }
  }
}

class SecretStream {
  final bindings.SecretStream _binding;

  SecretStream([bindings.SecretStream binding]) : _binding = binding ?? bindings.SecretStream();

  /// Generates a key for a secret stream.
  UnmodifiableUint8ListView keyGen() {
    return freeZero1(Uint8Array.allocate(count: _binding.keyBytes), (keyPtr) {
      return UnmodifiableUint8ListView(Uint8List.fromList(keyPtr.view));
    });
  }

  PushStream resumePush(Uint8List state, {Uint8List header}) {
    return PushStream.resume(state, header: header, binding: _binding);
  }

  PushStream push(Uint8List key) {
    return PushStream(key, binding: _binding);
  }

  PullStream pull(Uint8List key, Uint8List header) {
    return PullStream(key, header, binding: _binding);
  }
}

mixin Rekey {
  bindings.SecretStream get _binding;

  Uint8List get _state;

  /// Generates a new key for the secret stream (see libsodium documentation).
  void rekey() {
    freeZero1(
      _state.asArray,
      (statePtr) {
        _binding.rekey(statePtr.rawPtr);
        _state.setAll(0, statePtr.view);
      },
    );
  }
}

/// Encryption stream
class PushStream with Rekey {
  @override
  final bindings.SecretStream _binding;
  @override
  final Uint8List _state;
  Uint8List _header;

  /// State of the stream. You can save [state] to [resume] at a later point
  /// or send it to another machine / thread to split up the workload.
  UnmodifiableUint8ListView get state => UnmodifiableUint8ListView(_state);

  /// Header of the stream. Required to initialize a [PullStream].
  UnmodifiableUint8ListView get header => UnmodifiableUint8ListView(_header);

  /// Resume the [PushStream] from a saved [state].
  PushStream.resume(this._state, {Uint8List header, bindings.SecretStream binding})
      : _header = header,
        _binding = binding ?? bindings.SecretStream() {
    checkExpectedLengthOf(_state.length, _binding.stateBytes, 'state');
    if (header != null) {
      checkExpectedLengthOf(_header.length, _binding.headerBytes, 'header');
    }
  }

  factory PushStream(Uint8List key, {bindings.SecretStream binding}) {
    final _binding = binding ?? bindings.SecretStream();

    return free1freeZero2(
      Uint8Array.allocate(count: _binding.headerBytes),
      key.asArray,
      Uint8Array.allocate(count: _binding.stateBytes),
      (headerPtr, keyPtr, statePtr) {
        final result = _binding.initPush(statePtr.rawPtr, headerPtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw InitStreamError();
        }

        final state = Uint8List.fromList(statePtr.view);
        final header = Uint8List.fromList(headerPtr.view);
        return PushStream.resume(state, header: header, binding: binding);
      },
    );
  }

  /// Pushes [message] into the stream. [message] cannot be longer than [msgBytesMax] (~256 GB).
  /// [additionalData] will not be encrypted but will be included in the computation
  /// of the authentication tag (see libsodium documentation).
  /// [tag] marks the status of the stream (see libsodium documentation).
  /// Throws [PushError] when pushing [message] into the stream fails.
  Uint8List push(Uint8List message, {Uint8List additionalData, Tag tag = Tag.message}) {
    return free3freeZero1(
      additionalData?.asArray,
      message.asArray,
      Uint8Array.allocate(count: message.length + _binding.aBytes), // cipherPtr
      _state.asArray,
      (adDataPtr, msgPtr, cipherPtr, statePtr) {
        final result = _binding.push(
          statePtr.rawPtr,
          cipherPtr.rawPtr,
          nullptr.cast(),
          msgPtr.rawPtr,
          message.length,
          adDataPtr.rawPtr,
          adDataPtr.length,
          tag.toNative(_binding),
        );
        if (result != 0) {
          throw PushError();
        }

        return Uint8List.fromList(cipherPtr.view);
      },
    );
  }
}

class PullResult {
  final Uint8List value;
  final Tag tag;

  PullResult._(this.value, this.tag);
}

/// Decryption stream
class PullStream with Rekey {
  @override
  final bindings.SecretStream _binding;

  @override
  final Uint8List _state;

  /// State of the stream. You can save [state] to [resume] at a later point
  /// or send it to another machine / thread to split up the workload.
  UnmodifiableUint8ListView get state => _state;

  /// Resume [PushStream] from a saved [state].
  PullStream.resume(this._state, {bindings.SecretStream binding}) : _binding = binding ?? bindings.SecretStream() {
    checkExpectedLengthOf(_state.length, _binding.stateBytes, 'state');
  }

  factory PullStream(Uint8List key, Uint8List header, {bindings.SecretStream binding}) {
    final _binding = binding ?? bindings.SecretStream();
    return free1freeZero2(
      header.asArray,
      Uint8Array.allocate(count: _binding.stateBytes),
      key.asArray,
      (headerPtr, statePtr, keyPtr) {
        final result = _binding.initPull(statePtr.rawPtr, headerPtr.rawPtr, keyPtr.rawPtr);
        if (result != 0) {
          throw InitStreamError();
        }
        return PullStream.resume(Uint8List.fromList(statePtr.view));
      },
    );
  }

  PullResult pullWithTag(Uint8List chunk, {Uint8List additionalData}) {
    return free4freeZero1(
      additionalData?.asArray,
      chunk.asArray,
      Uint8Array.allocate(count: chunk.length - _binding.aBytes),
      Uint8Array.allocate(),
      _state.asArray,
      (aPtr, cPtr, messagePtr, tagPtr, statePtr) {
        final result = _binding.pull(
          statePtr.rawPtr,
          messagePtr.rawPtr,
          nullptr.cast<Uint64>(),
          tagPtr.rawPtr,
          cPtr.rawPtr,
          chunk.length,
          aPtr.rawPtr,
          aPtr.length,
        );
        if (result != 0) {
          throw PullError();
        }
        return PullResult._(Uint8List.fromList(messagePtr.view), TagNative.fromNative(tagPtr.view.first, _binding));
      },
    );
  }

  /// Pulls a message out of the stream. [additionalData] must be the same given to [push].
  /// If [readTag] is true [tag] will be updated with the tag of this message; otherwise
  /// [tag] stays null
  /// Throws [PullError] when pulling message out of stream fails.
  Uint8List pull(Uint8List chunk, {Uint8List additionalData}) {
    return free3freeZero1(
      additionalData?.asArray,
      chunk.asArray,
      Uint8Array.allocate(count: chunk.length - _binding.aBytes),
      _state.asArray,
      (aPtr, cPtr, messagePtr, statePtr) {
        final result = _binding.pull(
          statePtr.rawPtr,
          messagePtr.rawPtr,
          nullptr.cast(),
          nullptr.cast(),
          cPtr.rawPtr,
          cPtr.length,
          aPtr.rawPtr,
          aPtr.length,
        );
        if (result != 0) {
          throw PullError();
        }
        return Uint8List.fromList(messagePtr.view);
      },
    );
  }
}
