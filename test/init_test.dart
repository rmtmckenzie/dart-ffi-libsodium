import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  test('Can initialize libsodium', () {
    LibSodium.init();
  });
}
