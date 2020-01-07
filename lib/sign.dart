/// Sign messages with public and secret key.
/// Maps libsodium's crypto_sign_* api.
library sign;

export 'src/sign.dart';
export 'src/bindings/sign.dart' show publicKeyBytes, secretKeyBytes;
export 'box.dart' show KeyPair;
