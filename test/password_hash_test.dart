import 'package:dart_sodium/password_hash.dart';
import 'package:dart_sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  LibSodium.init();
  final pwhash = PasswordHash();

  test('Hash and verify password', () {
    final hash =
        pwhash.store('my password', opsLimit: pwhash.memLimit.interactive);
    final isValid = pwhash.verify(hash, 'my password');

    expect(isValid, true);
  });
}
