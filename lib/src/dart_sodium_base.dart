import 'dart:ffi' as ffi;

final libsodium = ffi.DynamicLibrary.open("libsodium");
var _isInitialized = false;

final _init = libsodium
    .lookupFunction<ffi.Int8 Function(), int Function()>("sodium_init");

void init() {
  if (_isInitialized) {
    return;
  }
  final result = _init();
  if (result < 0) {
    throw Exception("""Initialization of dart_sodium failed: $result 
       Without initialization, dart_sodium isn't safe to use!""");
  }
  _isInitialized = true;
}
