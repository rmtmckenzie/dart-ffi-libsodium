import 'dart:ffi' as ffi;

ffi.DynamicLibrary libsodium;
var _isInitialized = false;

final _init = libsodium
    .lookupFunction<ffi.Int8 Function(), int Function()>("sodium_init");

/// Initializes sodium. This function should be called before any other function of sodium.
/// Calling this function several times has no effect and can be safely done.
void init(String path) {
  if (_isInitialized) {
    return;
  }
  libsodium = ffi.DynamicLibrary.open(path);
  final result = _init();
  if (result < 0) {
    throw Exception("Initialization of dart_sodium failed");
  }
  _isInitialized = true;
}
