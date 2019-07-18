import 'dart:ffi' as ffi;

final libsodium = ffi.DynamicLibrary.open("libsodium");
var _isInitialized = false;

final _init =
    libsodium.lookupFunction<int Function(), int Function()>("sodium_init");
