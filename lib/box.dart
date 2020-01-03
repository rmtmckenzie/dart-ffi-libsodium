/// Encrpyt messages with public and secret key.
/// Maps libsodium's crypto_box_* api.
library box;

export 'src/box.dart';
export 'src/bindings/box.dart'
    show nonceBytes, publicKeyBytes, secretKeyBytes, seedBytes;
