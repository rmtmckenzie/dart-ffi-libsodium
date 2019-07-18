import 'dart:ffi' as ffi;

final libsodium = ffi.DynamicLibrary.open("libsodium");
var _isInitialized = false;

final _init =
    libsodium.lookupFunction<int Function(), int Function()>("sodium_init");

void init() {
  if (_isInitialized) {
    return;
  }
  final result = _init();
  if (result < 0) {
    throw Exception("""Initialization of sodium failed: $result 
        Don't rely on dart_sodium at this point because its safety cannot be guaranteed""");
  }
  _isInitialized = true;
}
