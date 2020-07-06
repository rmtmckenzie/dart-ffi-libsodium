import 'package:dart_sodium/password_hash.dart';

void main(List<String> args) {
  final pwHash = PasswordHash();

  final hash = pwHash.store('my password', opsLimit: pwHash.opsLimit.moderate);

  print("Is valid: ${pwHash.verify(hash, "my password")}");
}
