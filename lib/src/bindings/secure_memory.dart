import 'dart:ffi';

import 'libsodium.dart';

typedef ZeroNative = Void Function(Pointer<Void> ptr, IntPtr size);
typedef ZeroDart = void Function(Pointer<Void> ptr, int size);

typedef LockNative = Void Function(Pointer<Void> ptr, IntPtr size);
typedef LockDart = void Function(Pointer<Void> ptr, int size);

typedef UnlockNative = Int16 Function(Pointer<Void> addr, IntPtr len);
typedef UnlockDart = int Function(Pointer<Void> addr, int len);

typedef MallocNative = Pointer<Void> Function(IntPtr size);
typedef MallocDart = Pointer<Void> Function(int size);

typedef AllocArrayNative = Pointer<Void> Function(IntPtr count, IntPtr size);
typedef AllocArrayDart = Pointer<Void> Function(int count, int size);

typedef FreeNative = Void Function(Pointer<Void> ptr);
typedef FreeDart = void Function(Pointer<Void> ptr);

typedef NoAccessNative = Int16 Function(Pointer<Void> ptr);
typedef NoAccessDart = int Function(Pointer<Void> ptr);

typedef ReadOnlyNative = Int16 Function(Pointer<Void> ptr);
typedef ReadOnlyDart = int Function(Pointer<Void> ptr);

typedef ReadWriteNative = Int16 Function(Pointer<Void> ptr);
typedef ReadWriteDart = int Function(Pointer<Void> ptr);

class SecureMemory {
  factory SecureMemory([LibSodium libSodium]) {
    return SecureMemory._((libSodium ?? LibSodium()).sodium);
  }

  SecureMemory._(DynamicLibrary sodium)
      : zero = sodium.lookup<NativeFunction<ZeroNative>>('sodium_memzero').asFunction(),
        lock = sodium.lookup<NativeFunction<LockNative>>('sodium_mlock').asFunction(),
        unlock = sodium.lookup<NativeFunction<UnlockNative>>('sodium_munlock').asFunction(),
        malloc = sodium.lookup<NativeFunction<MallocNative>>('sodium_malloc').asFunction(),
        allocArray = sodium.lookup<NativeFunction<AllocArrayNative>>('sodium_allocarray').asFunction(),
        free = sodium.lookup<NativeFunction<FreeNative>>('sodium_free').asFunction(),
        noAccess = sodium.lookup<NativeFunction<NoAccessNative>>('sodium_mprotect_noaccess').asFunction(),
        readOnly = sodium.lookup<NativeFunction<ReadOnlyNative>>('sodium_mprotect_readonly').asFunction(),
        readWrite = sodium.lookup<NativeFunction<ReadWriteNative>>('sodium_mprotect_readwrite').asFunction();

  final ZeroDart zero;
  final LockDart lock;
  final UnlockDart unlock;
  final MallocDart malloc;
  final AllocArrayDart allocArray;
  final FreeDart free;
  final NoAccessDart noAccess;
  final ReadOnlyDart readOnly;
  final ReadWriteDart readWrite;
}
