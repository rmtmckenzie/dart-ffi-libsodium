/// Generates sequences of (pseudo-)random bytes.
/// Maps libsodium's crypto_randombytes_* api.
library random_bytes;

export 'src/random_bytes.dart';
export 'src/bindings/random.dart' show seedBytes;
