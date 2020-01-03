/// Encrypt messages with a secret key.
/// Maps libsodium's crypto_secret_box_* api.
library secret_box;

export 'src/secret_box.dart';
export 'src/bindings/secretbox.dart' show keyBytes, macBytes, nonceBytes;
