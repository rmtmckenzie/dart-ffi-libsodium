dart_sodium is a wrapper library for the Sodium cryptography library (libsodium) written in C (https://libsodium.gitbook.io/). Below you find a list of covered libsodium apis and their counterparts in dart_sodium. Every api is wrapped inside its own mini library.

### Secret-key cryptography

|topic       | libsodium api | dart_sodium lib |
|------------|:---------------:|-----------------:|
|Authenticated encryption | crypto_secretbox_* | secret_box|
|Encrypted streams | crypto_secretstream_* | secret_stream|
|Authentication | crypto_auth_* | auth

### Public-key cryptography 

|topic       | libsodium api | dart_sodium lib |
|------------|:--------------:|-----------------:|
|Authenticated encryption | crypto_box_*| box   |
|Public-key signatures | crypto_sign_* | sign  |

### Hashing
|topic       | libsodium api | dart_sodium lib |
|------------|:--------------:|-----------------:|
|Generic hash| crypto_generichash_* | generic_hash|


### Rest

|topic       | libsodium api | dart_sodium lib |
|------------|:---------------:|-----------------:|
|Random data | crypto_randombytes_* | random_bytes|
|Password hashing| crypto_pwhash_* | pwhash|



Not every api is fully covered yet. dart_sodium tries to resemble libsodium as much as possible while following Dart's conventions. To avoid repetition dart_sodium's api documentation is rather terse. For more information about apis and algorithms and when to use them I would recommend the libsodium documentation.

# Running

On mac, must unsign dart executable:
```bash
codesign --remove-signature `which dart`
```

Also, on mac only loading must include `.dylib`. Default no-arg init handles
this automatically.

# How to use

Before calling any other function of dart_sodium, you should call
````Dart
import 'package:dart_sodium/sodium.dart' as sodium;

void main(){
    sodium.init()
}
````
to initialize a suitable random number generator. You just need to do this once per application, not per isolate. Calling `init()` multiple times has no effect. 

You have to install libsodium on your machine. If you use Linux or MacOS you can use the corresponding package manager to do that; in the case of Windows you have to manually copy the .dll into the System32 directory. Alternatively you could copy the shared library into the root directory of your application.

## Examples
### Secret box
````Dart
final key = secret_box.keyGen();
final msg = utf8.encode('hello world');

final nonce = random_bytes.buffer(secret_box.nonceBytes);
final c = secret_box.easy(msg, nonce, key);

final decrypted = secret_box.openEasy(c, nonce, key);
````
### Secret stream
````Dart
final key = secret_stream.keyGen();
final message = utf8.encode('hello world');
final message2 = utf8.encode('hello to the world');

final pushStream = secret_stream.PushStream(key);
final encChunk = pushStream.push(message);
final encChunk2 = pushStream.push(message2, tag: secret_stream.Tag.finalize);

final pullStream = secret_stream.PullStream(key, pushStream.header);
final decChunk = pullStream.pull(encChunk);
final decChunk2 = pullStream.pull(encChunk2);
````

### Password hash
````Dart
final password = utf8.encode('my password');
final hash = pwhash.store(
    password, pwhash.OpsLimit.interactive, pwhash.MemLimit.interactive);
final isValid = pwhash.verify(hash, password);
````
# Security

Please keep in mind that when snapshotted, `random_bytes` might produce the same output (https://libsodium.gitbook.io/doc/generating_random_data#note).

Since Dart uses a garbage collector you should take measures against heap dump attacks. Be aware that keys and other sensitive information 
might be in memory for a long time. The GC can move memory around to optimize the layout (eg defragmentation), so overwriting sensitive information
might not have the desired effect. In short: Only use dart_sodium on machines / platforms you fully trust and which take approrpiate measures to isolate them
from the outside world. Don't use it for client software like a password manager.
