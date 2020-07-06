import 'dart:typed_data';

import 'package:meta/meta.dart';

class EncryptResult {
  final Uint8List cipher;
  final Uint8List nonce;

  EncryptResult({@required this.cipher,@required  this.nonce});
}

class SodiumException implements Exception {}