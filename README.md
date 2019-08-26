Blake2 library. Two ways:
```nim
var b: Blake2b
blake2b_init(b, 4, "key", 3)
blake2b_update(b, "data", 4)
assert($blake2b_final(b) == getBlake2b("data", 4, "key"))
```

