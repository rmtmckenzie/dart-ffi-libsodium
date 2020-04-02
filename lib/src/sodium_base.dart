import 'bindings/sodium.dart' as bindings;
import 'package:ffi/ffi.dart' as ffi;

class InitException implements Exception {
  @override
  String toString() {
    return 'Failed to initialize libsodium';
  }
}

bool Function() _initWrapper() {
  if (version.substring(0, 2) != '1.') {
    throw StateError(
        'The installed version of libsodium must be > 1.0.18 and < 2: $version');
  }
  var isInit = false;
  return () {
    if (isInit) {
      return true;
    }
    final result = bindings.init();
    if (result == -1) {
      throw InitException();
    }
    isInit = true;
    return false;
  };
}

/// Initializes a random number generator for dart_sodium. Must be called before
/// any other function of dart_sodium. Calling it multiple times has no effect.
/// The return value indicates if dart_sodium was already initialized.
/// Throws [InitException] when initialization fails.
final init = _initWrapper();

/// The version of the installed dynamic library
final version = () {
  return ffi.Utf8.fromUtf8(bindings.version.cast());
}();
