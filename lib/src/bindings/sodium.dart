import 'dart:ffi';

final sodium = DynamicLibrary.open("libsodium");

final init =
    sodium.lookupFunction<Int16 Function(), int Function()>("sodium_init");
final version =
    sodium.lookupFunction<Pointer<Uint8> Function(), Pointer<Uint8> Function()>(
        'sodium_version_string');
