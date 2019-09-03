This is an easy to use wrapper for libsodium (version 1.0.18). It resembles the original interface (while being in compliance with Dart's nameing conventions) and uses object-orientation where it makes sense.

As for now dart_sodium offers the following features:
- password hashing (Argon2)
- message authentication / signing
- secretbox and secretstream interface (symmetric authenticated encryption)

Please notice that this work has been done to the best of my abilities. This has not been reviewed by external security professionals. If you are one please feel free to review and test this library in any way you see fit. I am new to open source and I see forward to any feedback.

## How to Use

Unfortunately pub doesn't have any solution for dealing with native dependencies yet. Dart resolves all paths to dynamic libraries relative to the main executable. Therefore you have to download a pre-build library for your system and use its path to initialize dart_sodium: https://libsodium.gitbook.io/doc/installation

For example when libsodium is in the root directory of your application:
````Dart
init("./libsodium");
````
Omit the platform specific extension which will be determined by the runtime.
