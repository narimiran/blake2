type
   Blake2b* = object
      hash: array[8, uint64]
      offset: array[2, uint64]
      buffer: array[128, uint8]
      buffer_idx: uint8
      hash_size: uint8

const Blake2bIV =
   [ 0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
     0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
     0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
     0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64 ]

const Sigma = [
   [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
   [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
   [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
   [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
   [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
   [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
   [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
   [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
   [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
   [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ],
   [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
   [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ] ]

proc inc(a: var array[2, uint64], b: uint8) =
   a[0] = a[0] + b
   if (a[0] < b): inc(a[1])

proc padding(a: var array[128, uint8], b: uint8) =
   for i in b..127: a[i] = 0

proc ror64(x: uint64, n: int): uint64 {.inline.} =
   result = (x shr n) or (x shl (64 - n))

proc G (v: var array[16, uint64],
        a,b,c,d: int, x,y: uint64)
       {.inline.} =
   v[a] = v[a] + v[b] + x
   v[d] = ror64(v[d] xor v[a], 32)
   v[c] = v[c] + v[d]
   v[b] = ror64(v[b] xor v[c], 24)
   v[a] = v[a] + v[b] + y
   v[d] = ror64(v[d] xor v[a], 16)
   v[c] = v[c] + v[d]
   v[b] = ror64(v[b] xor v[c], 63)

proc compress(c: var Blake2b, last: int = 0) =
   var input, v: array[16, uint64]
   for i in 0..15:
      input[i] = cast[ptr uint64](addr(c.buffer[i*8]))[]
   for i in 0..7:
      v[i] = c.hash[i]
      v[i+8] = Blake2bIV[i]
   v[12] = v[12] xor c.offset[0]
   v[13] = v[13] xor c.offset[1]
   if (last == 1): v[14] = not(v[14])
   for i in 0..11:
      G(v, 0, 4,  8, 12, input[Sigma[i][0]],  input[Sigma[i][1]])
      G(v, 1, 5,  9, 13, input[Sigma[i][2]],  input[Sigma[i][3]])
      G(v, 2, 6, 10, 14, input[Sigma[i][4]],  input[Sigma[i][5]])
      G(v, 3, 7, 11, 15, input[Sigma[i][6]],  input[Sigma[i][7]])
      G(v, 0, 5, 10, 15, input[Sigma[i][8]],  input[Sigma[i][9]])
      G(v, 1, 6, 11, 12, input[Sigma[i][10]], input[Sigma[i][11]])
      G(v, 2, 7,  8, 13, input[Sigma[i][12]], input[Sigma[i][13]])
      G(v, 3, 4,  9, 14, input[Sigma[i][14]], input[Sigma[i][15]])
   for i in 0..7:
      c.hash[i] = c.hash[i] xor v[i] xor v[i+8]
   c.buffer_idx = 0

proc blake2b_update*(c: var Blake2b, data: cstring|string|seq|uint8, data_size: int) =
   for i in 0..<data_size:
      if c.buffer_idx == 128:
         inc(c.offset, c.buffer_idx)
         compress(c)
      when data is cstring or data is string:
         c.buffer[c.buffer_idx] = ord(data[i]).uint8
      elif data is seq:
         c.buffer[c.buffer_idx] = data[i]
      else:
         c.buffer[c.buffer_idx] = data
      inc(c.buffer_idx)

proc blake2b_init*(c: var Blake2b, hash_size: uint8,
                   key: cstring = nil, key_size: int = 0) =
   assert(hash_size >= 1'u8 and hash_size <= 64'u8)
   assert(key_size  >= 0    and key_size  <= 64)
   c.hash = Blake2bIV
   c.hash[0] = c.hash[0] xor 0x01010000 xor cast[uint64](key_size shl 8) xor hash_size
   c.hash_size = hash_size
   if key_size > 0:
      blake2b_update(c, key, key_size)
      padding(c.buffer, c.buffer_idx)
      c.buffer_idx = 128

proc blake2b_final*(c: var Blake2b): seq[uint8] =
   result = @[]
   inc(c.offset, c.buffer_idx)
   padding(c.buffer, c.buffer_idx)
   compress(c, 1)
   for i in 0 ..< c.hash_size.int:
      result.add(cast[uint8]((c.hash[i div 8] shr (8 * (i and 7)) and 0xFF)))
   zeroMem(addr(c), sizeof(c))

proc `$`*(d: seq[uint8]): string =
  const digits = "0123456789abcdef"
  result = ""
  for i in 0..high(d):
    add(result, digits[(d[i] shr 4) and 0xF])
    add(result, digits[d[i] and 0xF])

proc getBlake2b*(s: string, hash_size: uint8, key: string = ""): string =
   var b: Blake2b
   blake2b_init(b, hash_size, cstring(key), len(key))
   blake2b_update(b, s, len(s))
   result = $blake2b_final(b)
