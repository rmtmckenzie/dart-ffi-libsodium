I made this thin wrapper around the (awsome) sodium library to check out the new (still experimental) FFI,
but also because cryptography is still a weak point of Dart and I needed something more sophisticated.

The interface resembles the original as good as possible but also follows Dart's naming conventions.
To make the library as generic and performant as possible it makes extensive use of the Uint8List instead of Strings.

Please notice that this work is done to the best of my abilities. This has not been reviewed by external security professionals. If you are one and also feel that Dart needs better cryptography please feel free to 
review and test this library in any way you see fit. I would be happy about any kind of suggestion and improvement.

Please also notice that this library is work in progress. So far there are only a few functions available.
But those are also the most commonly used ones, and I don't plan to change the interface.

I might do some higher level (object oriented) abstractions over some stuff, but at the moment I don't see the point. Libsodium already provides high level functions for most applications. But if you think there might be a solid use case, feel free to deploy your package with a higher level api.

I also try to do proper documentation (only just learned to use dartdoc). You can also look at libsodium's documentation for further information: https://libsodium.gitbook.io/doc/