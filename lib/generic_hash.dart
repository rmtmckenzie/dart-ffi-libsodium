/// Fingerprint messages (eg files).
/// Maps libsodium's crypto_generichash_* api
library generic_hash;

export 'src/generic_hash.dart';
export 'src/bindings/generic_hash.dart'
    show
        genericHashBytes,
        genericHashBytesMax,
        genericHashBytesMin,
        keyBytes,
        keyBytesMax,
        keyBytesMin;
