import "package:dart_sodium/dart_sodium.dart" as sodium;

void init() {
  sodium.init("./libsodium");
}
