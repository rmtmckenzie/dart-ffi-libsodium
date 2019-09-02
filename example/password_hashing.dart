import 'package:dart_sodium/dart_sodium.dart';
import 'package:dart_sodium/random.dart' as rand;
import 'package:dart_sodium/pwhash.dart' as pwhash;

void main() {
  init("./libsodium");

  final password = rand.buffer(16);
  final hash = pwhash.store(
      password, pwhash.OpsLimit.interactive, pwhash.MemLimit.interactive);

  final isValid = pwhash.storeVerify(hash, password);
  assert(isValid == true);
}
