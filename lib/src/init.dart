import 'bindings/sodium.dart' as bindings;

class InitException implements Exception {
  @override
  String toString() {
    return 'Failed to initialize libsodium';
  }
}

bool Function() _initWrapper() {
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
bool init() => _initWrapper()();
