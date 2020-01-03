import 'dart:ffi';

final sodium = DynamicLibrary.open("libsodium");

final init =
    sodium.lookupFunction<Int16 Function(), int Function()>("sodium_init");
