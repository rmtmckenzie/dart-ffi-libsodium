/// Encrypt messages with a secret key as a stream.
/// Maps libsodium's crypto_secretstream_* api
library secret_stream;

export 'src/secret_stream.dart';
export 'src/bindings/secretstream.dart' show aBytes, keyBytes, msgBytesMax;
