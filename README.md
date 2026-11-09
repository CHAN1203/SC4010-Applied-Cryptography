# LeakyVault — build weak AES, then break it

SC4010 Applied Cryptography mini-project. `LeakyVault.ipynb` builds a small AES
file-locker that uses AES carelessly, then breaks it five ways **without ever
using the key**, and ends by checking which of those mistakes AES-GCM fixes.

This README is our cheat sheet for the live presentation: the concepts in a few
words, the questions most likely to test our understanding (with answers and
where the code is), and which knobs to turn if we want to change a demo.

---

## Running it

```powershell
python -m venv .venv
.venv\Scripts\pip install pycryptodome matplotlib pillow numpy ipykernel
```

Open `LeakyVault.ipynb` in VS Code or Jupyter, pick the `.venv` kernel, and **Run
All** (about 10–15 seconds, mostly the two seed brute-force loops in §4a and
§4c). Run it top to bottom: later cells reuse helpers and variables from earlier
ones.

`DEMO = True` (§0) makes every key, nonce and IV come from a fixed seed, so the
outputs are identical on every run. The only exception is §4c, which uses real OS
randomness on purpose: its keys and timing change each run, but the attacks
always fail.

---

## Concepts in a few words

| Term | In a few words |
|---|---|
| **AES** | A block cipher: with a key, it scrambles exactly 16 bytes into 16 bytes. Secure on its own; everything else is about *how* you use it on longer data (the "mode"). |
| **ECB** | Encrypt each 16-byte block separately with the same key. Same input block → same output block, so patterns leak. |
| **CBC** | XOR each plaintext block with the previous *ciphertext* block before encrypting; the first block uses a random **IV**. Hides patterns, but needs padding and has no integrity check. |
| **CTR** | Encrypt a counter (`nonce ‖ 0, nonce ‖ 1, …`) to make a **keystream**, then XOR it with the data. Turns AES into a stream cipher; no padding needed. |
| **Nonce / IV** | A per-message value that makes the same key produce different output each time. A nonce must never repeat under one key; a CBC IV must also be unpredictable. |
| **PKCS#7 padding** | Fill the last block up to 16 bytes with `N` copies of the byte `N` (a full extra block if already aligned). Decryption checks and strips it. |
| **Two-time / many-time pad** | Reusing a keystream: `C1 ⊕ C2 = P1 ⊕ P2`, so the key cancels out and the plaintexts can be pulled apart. |
| **Mersenne Twister (MT19937)** | Python's `random`. Fast and statistically good, but **not cryptographic**: its state is 624 32-bit words, and each output is an invertible "tempering" of one word, so 624 outputs reveal the state and every future output. |
| **CSPRNG** | A cryptographically secure random generator (`os.urandom`, `secrets`): past outputs reveal nothing about future ones. The only correct source for keys and nonces. |
| **Padding oracle** | Any yes/no signal (error message, status code, timing) that tells an attacker whether CBC padding was valid. Enough to decrypt the whole message, byte by byte. |
| **Malleability / bit-flipping** | Changing the ciphertext changes the plaintext in a predictable way. In CBC, flipping a bit of the IV flips the same bit of plaintext block 1. |
| **AEAD** | Authenticated Encryption with Associated Data: encrypts *and* attaches a tag, so any tampering is detected and rejected before the plaintext is used. |
| **GCM** | The common AEAD mode: CTR for encryption + **GHASH** (a polynomial MAC with hash key `H = AES_K(0)`) for the tag. Fast, but catastrophic if a nonce repeats. |
| **SIV / AES-GCM-SIV** | "Synthetic IV": the IV is derived from the message itself (RFC 8452). If a nonce repeats, the only leak is whether two messages were identical; no keystream reuse, no key leak. Costs two passes over the data. |

---

## Top 10 Q&A — answer and where it is in the code

The ten questions most likely to test whether we understand our own code and our
own argument. Code pointers use the notebook section (§) and the function or
variable name, so `Ctrl+F` finds them.

**1. Why can we still see the face after ECB encryption?** *(§2)*
The image is greyscale, 1 byte per pixel, so one AES block = 16 horizontal
pixels. Large one-colour areas give many identical blocks, and ECB turns
identical plaintext blocks into identical ciphertext blocks. CBC hides this
because each block is XORed with the previous ciphertext block first.
→ `ecb_bytes` / `cbc_bytes`; proven numerically by `count_repeated_blocks`
(4060 repeats for ECB vs 0 for CBC).

**2. How do you recover the CTR messages with no key and no guessing, and why are some characters `.`?** *(§3)*
Same nonce → same keystream, so `C1 ⊕ C2 = P1 ⊕ P2` and the key cancels out. To
recover the keystream itself: a space (`0x20`) XORed with a letter gives the same
letter with its case flipped, still a letter. In each column, the message whose
byte XORs into letters with most of the others probably has a space there, so
that keystream byte = `ciphertext byte ⊕ 0x20`. A `.` means the best score was
below `threshold`. Column 0 is all `.` because every message starts with a
letter, so no message has a space there. More messages or English
letter-frequency scoring would fill the gaps.
→ `recover_keystream`, `threshold`.

**3. Mersenne Twister's period is 2¹⁹⁹³⁷ − 1. Why is it still weak, and would a good seed fix it?** *(§4 intro, §4a, §4b)*
Period isn't the problem; there are two other weaknesses, and a good seed fixes
only one:
- **4a, small seed:** the key is fully decided by the seed, so we search 100,000
  seeds instead of 2¹²⁸ keys. A good seed fixes this.
- **4b, predictable output:** the attack never needs the seed, only the outputs.
  The cell even seeds from `os.urandom(16)` when `DEMO = False`, and the key is
  still recovered. A good seed does **not** fix this; only a CSPRNG does.

→ `weak_key_from_seed`, `brute_force_seed`, the `random.seed(...)` line in §4b.

**4. Walk us through the MT attack: why 624, what does `untemper` do, and why `+ [624]`?** *(§4b)*
MT19937's state is 624 words of 32 bits. Each 32-bit output is one state word
passed through four reversible "tempering" steps (shift-and-XOR, some with a mask).
`untemper` undoes them in reverse order, so 624 consecutive outputs = the whole
state. `+ [624]` is the position index meaning "all words used up", so the clone's
next call regenerates the state exactly as the real generator does, and its next
four outputs are the secret key.
→ `untemper`, `undo_rshift_xor`, `undo_lshift_and_xor`, `clone.setstate(...)`.

**5. How does a single yes/no from the oracle reveal a plaintext byte?** *(§5)*
In CBC, `P = D(C) ⊕ previous block`. We send the real target block with a fake
previous block (`forged`) and try all 256 values for one byte. When the oracle
says "padding valid", that byte must have decrypted to the padding value (e.g.
`0x01`), so `D(C)[byte] = guess ⊕ pad`. XOR that with the *real* previous block →
real plaintext byte. Then we set the known bytes to decrypt to `0x02`, `0x03`, …
and move left. The first block works too because the IV acts as its "previous
block" and the IV is public. At most 256 queries per byte (about 128 on average), so
roughly 8,000 for our 4-block message. The attacker never learns the key, only the plaintext.
→ `padding_oracle`, `attack_one_block` (`inter`, `forged`, `guess`).

**6. What is the extra check when `pad == 1` for?** *(§5)*
A "yes" on the last byte usually means it decrypted to `0x01`, but it could also
mean the last two bytes happen to be `0x02 0x02` (also valid padding). Flipping the
second-to-last byte and asking again rules that out: real `0x01` padding stays
valid, an accidental `0x02 0x02` doesn't. Without this check, the attack can
occasionally recover a wrong byte.
→ the `if pad == 1:` block in `attack_one_block`.

**7. Why does flipping one IV bit turn `admin=0` into `admin=1`, and can you do it to later blocks?** *(§6)*
Block 1 is `P1 = D(C1) ⊕ IV`. XOR is linear, so XORing `'0' ⊕ '1'` into the IV at
the same position XORs it into the plaintext, with no key needed. For later blocks
you flip bits in the *previous ciphertext block* instead, but that block then
decrypts to garbage. Flipping the IV is the clean case. CBC never notices because
it gives secrecy only, not integrity.
→ `pos`, `delta`, `evil_iv`.

**8. Why does GCM fix bugs #1, #4 and #5 but not #2 and #3?** *(§7)*
GCM fixes *structure*: it is CTR-based (no repeated blocks, so no ECB leak), has no
padding (no padding oracle), and its tag rejects any tampering (the bit-flip is
rejected by `decrypt_and_verify`). It cannot fix *inputs*: a repeated nonce still
gives a repeated keystream (the two-time pad comes back), and a guessable key is
guessable in any mode. That is our main message: a good mode fixes careless
structure, not bad randomness. AES-GCM-SIV is the answer for nonce reuse: it
derives the IV from the message, so reuse only reveals whether two messages were
identical.
→ the §7 code cell and the "What GCM does and does not fix" table.

**9. You say nonce reuse also leaks the GCM auth key. Where is that shown?** *(§7)*
It is **not** demonstrated in the code, only stated. Be upfront about this. The
idea: with the same nonce, XORing the two tags cancels the encrypted counter block
and leaves a polynomial equation in the hash key `H`. Solving it gives `H`, which
lets the attacker forge valid tags (Joux's "forbidden attack").
→ the `"auth key leaks too"` print and the GCM table.

**10. Your notebook uses `random.Random` for its own keys in DEMO mode. Isn't that the same bug you're attacking?** *(§0, §4c)*
Yes, on purpose, so the live demo gives the same output every time. `rand_bytes`
switches to `os.urandom` when `DEMO = False`, and its docstring says real code must
never use a seeded generator. §4c then shows the fix: with keys from `secrets`, the
same seed search finds nothing and the MT clone predicts the wrong key. That shows
these attacks fail; it doesn't *prove* a CSPRNG is secure, which comes from its
design.
→ `rand_bytes` in §0, the §4c cell.

---

## Key functions by partner

The functions each of us should be able to explain line by line. The split
follows the notebook's suggestion: Partner A takes bad modes and bad randomness,
Partner B takes the padding oracle and integrity. "Q" numbers point to the
matching Top 10 answer for more depth.

### Partner A — bad modes and bad randomness (§2–§4)

**`count_repeated_blocks(ciphertext)`** — §2
Cuts the ciphertext into 16-byte blocks and returns
`len(blocks) - len(set(blocks))`, the number of duplicate blocks. A good mode
gives 0. ECB on our picture gives 4060, which detects ECB without looking at the
image. *(Q1)*

**`vault_encrypt_ctr(key, nonce8, data)`** — §1
`Counter.new(64, prefix=nonce8, initial_value=0)` builds each 16-byte counter
block as an 8-byte nonce + an 8-byte counter starting at 0. AES encrypts those
blocks into a keystream that is XORed with the data. The keystream depends only on
`(key, nonce)`, so reusing the nonce reuses the keystream. *(Q2)*

**`recover_keystream(cts)`** — §3
Works column by column, up to the shortest ciphertext. For column `j` it tries
each message `i` as "the one with a space here" and counts how many other messages
`k` make `cts[i][j] ^ cts[k][j]` a letter. That XOR equals `P_i ⊕ P_k` because the
keystream cancels. The message with the highest count wins, and the keystream byte
is `cts[i][j] ^ 0x20`. It also returns the count as `confidence`, which the print
loop compares with `threshold` to decide whether to show `.`. *(Q2)*

**`weak_key_from_seed(seed)`** — §1
`random.Random(seed).getrandbits(128)` converted to 16 bytes. The same seed always
gives the same key, so the key has only as much entropy as the seed.

**`brute_force_seed(ciphertext, iv, max_seed)`** — §4a
Tries every seed from 0 to `max_seed`: build the key with `weak_key_from_seed`,
decrypt in CBC, strip the padding. A wrong key almost always fails the padding
check (`pkcs7_unpad` raises `ValueError`, which is caught). If the padding passes
and every byte is printable text, it returns that seed and plaintext; otherwise
`(None, None)`. §4c reuses it against a CSPRNG key, where it returns `None`. *(Q3)*

**`undo_rshift_xor(y, shift)`** — §4b
Inverts `y = x ^ (x >> shift)`. The top `shift` bits of `y` are just the top bits
of `x`, because nothing was XORed into them. It rebuilds `x` from bit 31 down:
each bit is `y`'s bit XOR the bit of `x` that is `shift` places higher, which has
already been recovered. *(Q4)*

**`undo_lshift_and_xor(y, shift, mask)`** — §4b
Inverts `y = x ^ ((x << shift) & mask)`. Same idea mirrored: rebuild from bit 0
up, and each bit is `y`'s bit XOR (the bit of `x` that is `shift` places lower AND
the mask bit). *(Q4)*

**`untemper(y)`** — §4b
MT's tempering applies four steps in order: right shift 11, left shift 7 with mask
`0x9D2C5680`, left shift 15 with mask `0xEFC60000`, right shift 18. `untemper`
undoes them in **reverse** order (18, 15, 7, 11) to get back one word of internal
state. *(Q4)*

**The clone lines** — §4b
`state = [untemper(x) for x in public_file_ids]` rebuilds all 624 state words.
`clone.setstate((3, tuple(state + [624]), None))` loads them into a fresh
generator: `3` is the state-format version, `624` is the position index ("all
words used up, regenerate on next call"), and `None` is an unused Gaussian cache.
The clone's next four `getrandbits(32)` calls are the secret key. *(Q4)*

### Partner B — padding oracle and integrity (§0, §5–§7)

**`pkcs7_pad(data)`** — §0
`n = 16 - len(data) % 16`, always 1 to 16, then appends `n` copies of byte `n`. If
the data is already a multiple of 16, a full extra block of `0x10` is added, so
unpadding is never ambiguous.

**`pkcs7_unpad(data)`** — §0
Reads the last byte as `n` and raises `ValueError("bad padding")` if `n` is not 1–16
or the last `n` bytes are not all `n`. That exception is the leak that the padding
oracle turns into a yes/no answer. *(Q5)*

**`padding_oracle(iv, ct)`** — §5
Plays the victim server: decrypts with `victim_key` and returns `True` if
`pkcs7_unpad` succeeds, `False` if it raises. The attacker treats it as a black
box and never sees the key or the plaintext. *(Q5)*

**`attack_one_block(prev_block, target_block)`** — §5
Recovers one plaintext block. `inter` collects `D(target_block)`, the AES output
before the CBC XOR. `forged` is a fake previous block we control. For
`pad = 1 … 16` (byte index `idx = 16 - pad`, right to left):
1. Set the already-known tail to `inter[k] ^ pad`, so those bytes decrypt to
   `pad`.
2. Try all 256 values of `forged[idx]` until the oracle says yes (with the extra
   check when `pad == 1`, *Q6*).
3. Record `inter[idx] = guess ^ pad`.

At the end, plaintext = `inter ⊕ prev_block` (the *real* previous block). *(Q5)*

**The driver loop** — §5
`blocks = [victim_iv] + [16-byte chunks of the ciphertext]`, then calls
`attack_one_block(blocks[i-1], blocks[i])` for each pair, so the IV serves as the
previous block for block 1. It joins the results and strips the padding at the
end. *(Q5)*

**The bit-flip lines** — §6
`pos = token.index(b"0")` finds the `0` after `admin=` (position 6).
`delta = ord("0") ^ ord("1")` is `0x01`, the XOR that turns `'0'` into `'1'`.
`evil_iv[pos] ^= delta` applies it to the IV. Since `P1 = D(C1) ⊕ IV`, the same
change appears in the plaintext. *(Q7)*

**The GCM cell** — §7
`encrypt_and_digest` returns the ciphertext plus a 16-byte tag.
`decrypt_and_verify` recomputes the tag and raises `ValueError` if anything
changed, so the bit-flip is rejected. The second half encrypts two messages with
the same nonce and shows `C1 ⊕ C2 = P1 ⊕ P2` still holds: GCM's encryption is CTR
underneath. *(Q8, Q9)*

---

## Where to change things

| Want to… | Change this | Section |
|---|---|---|
| Get different (but still reproducible) keys | `DEMO_SEED` | §0 |
| Use real randomness everywhere | `DEMO = False` (§4b then reseeds from `os.urandom`; still recovered) | §0 |
| Change the ECB picture | `make_picture` (keep 256 × 256 and large solid regions) | §2 |
| Change the two-time-pad messages | `m1`, `m2`, `guess_m1` | §3 |
| Make the many-time pad cleaner or harder | the `messages` list (more messages, more spaces = fewer dots), `threshold` | §3 |
| Change the weak seed | `true_seed`; must stay below `max_seed` in `brute_force_seed` | §4a |
| Change the padding-oracle secret | `secret_msg` (any length; time grows with the number of blocks) | §5 |
| Change the bit-flip target | `token` (must fit in 16 bytes), `pos`, and the `delta` characters | §6 |
| Change the GCM demo messages | `p1`, `p2` (must be the same length for the XOR comparison) | §7 |

After any change, use **Run All**, not a single cell. Several cells reuse names
like `key`, `iv` and `locked`, and each later section overwrites them.
