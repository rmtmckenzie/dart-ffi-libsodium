import 'dart:ffi' as ffi;

final libsodium = ffi.DynamicLibrary.open("libsodium");
var _isInitialized = false;

final _init = libsodium
    .lookupFunction<ffi.Int8 Function(), int Function()>("sodium_init");

/// Initialize sodium. This function should be called before any other function of sodium.
/// Calling this function several times has no effect and can be safely done.
/// Initialization is required for the randomn number generator to work correctly
/// and sodium to be thread safe. Failing to initialize sodium could result in unsafe results.
/// Should sodium (for whatever reasons) fail to initialize, you should disregard any vaulues
/// acquired from it.
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
