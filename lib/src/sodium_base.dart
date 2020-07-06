import 'package:dart_sodium/src/shared.dart';
import 'package:ffi/ffi.dart' as ffi;

import 'bindings/libsodium.dart' as bindings;

class InitException implements SodiumException  {
  @override
  String toString() {
    return 'Failed to initialize libsodium';
  }
}

class LibSodium {
  final bindings.LibSodium binding;

  LibSodium._(this.binding);

  factory LibSodium() {
    return LibSodium._(bindings.LibSodium());
  }

  /// Initializes a random number generator for libsodium. Must be called before
  /// any other function of dart_sodium. Not doing so is a programming error, which
  /// can result in security risks.
  ///
  /// It only needs to be called once per application.
  /// Calling it multiple times, even from different isolates, has no effect.
  /// The return value indicates if dart_sodium was already initialized.
  /// Throws [InitException] when initialization fails.
  factory LibSodium.init({String name}) {
    final binding = bindings.LibSodium.open(name);
    final result = binding.init();
    if (result != 0) {
      throw InitException();
    }
    final libSodium =  LibSodium._(binding);
    final version = libSodium.version;
    if (version.substring(0, 2) != '1.') {
      throw StateError('The installed version of libsodium must be > 1.0.18 and < 2: $version');
    }
    return libSodium;
  }

  /// Version string of the installed dynamic library of libsodium
  String get version {
    return ffi.Utf8.fromUtf8(binding.versionString.cast());
  }
}