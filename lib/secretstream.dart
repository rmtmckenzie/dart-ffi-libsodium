import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

class _SecretBoxData {
  final Pointer<Uint8> _header;
  final Pointer<_State> _state;
  const _SecretBoxData(this._state, this._header);
  Uint8List get header => UnsignedCharToBuffer(_header, _headerBytes);
}

Uint8List keyGen() {
  Pointer<Uint8> keyPtr;
  try {
    keyPtr = allocate(count: keyBytes);
    _keyGen(keyPtr);
    return UnsignedCharToBuffer(keyPtr, keyBytes);
  } finally {
    keyPtr?.free();
  }
}

_SecretBoxData initPush(Uint8List key) {
  assert(key.length == keyBytes, "Key hasn't expected length [keyBytes]");
  Pointer<Uint8> keyPtr, headerPtr;
  Pointer<_State> statePtr;
  try {
    keyPtr = BufferToUnsignedChar(key);
    headerPtr = allocate(count: _headerBytes);
    statePtr = allocate(count: _stateBytes);
    int initResult = _initPush(statePtr, headerPtr, keyPtr);
    if (initResult != 0) {
      headerPtr?.free();
      throw Exception("SecretBox init failed");
    }
    return _SecretBoxData(statePtr, headerPtr);
  } finally {
    keyPtr?.free();
  }
}

Uint8List push(Uint8List data, _SecretBoxData state,
    [Uint8List additionalData, int tag = 0]) {
  Pointer<Uint8> dataPtr, adPtr, cPtr;
  try {
    dataPtr = BufferToUnsignedChar(data);
    final cLen = data.length + _aBytes;
    cPtr = allocate(count: cLen);
    var adLen = 0;
    if (additionalData != null) {
      adLen = additionalData.length;
      adPtr = BufferToUnsignedChar(additionalData);
    }

    int pushResult = _secretStreamPush(
        state._state, cPtr, null, dataPtr, data.length, adPtr, adLen, tag);
    if (pushResult != 0) {
      throw Exception("SecretBox push failed");
    }
    return UnsignedCharToBuffer(cPtr, cLen);
  } finally {
    dataPtr?.free();
    adPtr?.free();
    cPtr?.free();
  }
}

_SecretBoxData initPull(Uint8List key, Uint8List header) {
  assert(key.length == keyBytes, "Key hasn't expected length");
  assert(header.length == _headerBytes, "Header hasn't expected length");
  Pointer<Uint8> keyPtr, headerPtr;
  Pointer<_State> statePtr;
  try {
    keyPtr = BufferToUnsignedChar(key);
    headerPtr = BufferToUnsignedChar(header);
    statePtr = allocate(count: _stateBytes);
    int initResult = _initPull(statePtr, headerPtr, keyPtr);
    if (initResult != 0) {
      headerPtr?.free();
      throw Exception("SecretBox init failed");
    }
    return _SecretBoxData(statePtr, null);
  } finally {
    keyPtr?.free();
    headerPtr?.free();
  }
}

Uint8List pull(_SecretBoxData state, Uint8List ciphertext) {
  Pointer<Uint8> dataPtr, adPtr, cPtr, tagPtr;
  try {
    final dataLen = ciphertext.length - _aBytes;
    dataPtr = allocate(count: dataLen);
    cPtr = BufferToUnsignedChar(ciphertext);
    tagPtr = allocate();
    adPtr = allocate();

    int pushResult = _secretStreamPull(
        state._state, dataPtr, null, tagPtr, cPtr, ciphertext.length, adPtr, 0);
    if (pushResult != 0) {
      throw Exception("SecretBox pull failed");
    }
    print(tagPtr.load<int>());
    return UnsignedCharToBuffer(dataPtr, dataLen);
  } finally {
    dataPtr?.free();
    adPtr?.free();
    tagPtr?.free();
    cPtr?.free();
  }
}

void main(List<String> args) {
  init();
  final key = keyGen();
  print(key);
  final state = initPush(key);
  print(state);
  final c1 = push(ascii.encode("hello"), state, null, _tagFinal);
  print(c1);

  final pstate = initPull(key, state.header);
  final p1 = pull(pstate, c1);
  print(p1);
}
