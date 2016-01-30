# Attacks against Hohha Dynamic XOR

Here will be a collection of examples demonstrating attacks against the Hohha
Dynamic XOR encryption algorithm.

## CPA and CCA Attacks

Chosen plain text (CPA) and chosen cipher text (CCA) attacks are equivalent
against this algorithm.  In other words, a method of attack using chosen plain
text is just as effective with chosen cipher text.  In any of the oracles for
CCA or CPA attacks, just change encryption `-e` to decryption `-d` or vice
versa, and the attack will still succeed.

For CPA or CCA attacks, the adversary is able to send plain text messages to be
encrypted, and receive the encrypted result, or vice versa.  The adversary is
not allowed to see the key or observe the operation of the algorithm.  The
adversary may only observe the result.  The adversary is only allowed to use
one operation, either encryption or decryption, not both.

In CPA attacks, the adversary gets to choose the plain text.  It is possible
that the adversary gets to choose the salt, too, but more likely the salt will
not be under control of the adversary.  It is still interesting to consider the
strength of the algorithm when the adversary can choose the salt.

In CCA attacks, the adversary gets to choose the cipher text.  Since the salt
and cipher text would be transferred in the same message, and the adversary can
choose the cipher text, it is realistic to assume that the adversary can affect
all parts of the message, including the salt.

### Key Recovery: Key Length

The key length is supposed to be secret information.  A CCA2 attack is provided
which will recover the key length.  This attack could be conducted as CCA1
(batch) instead of CCA2 (adaptive), because the attack queries do not depend on
previous responses.

```
# choose a secret key
vi oracle-length.sh

# recover the key length with CCA2
./solve-length.py
```

The moving pointer is initialized by multiplying the third and last bytes of
salt, modulo the key length.  This attack takes advantage of the fact that some
products are equivalent, modulo the key length.  For example, if the key length
is 256, then zero times zero is equal to two times 128, four times 64, eight
ties 32, etc.  But, zero is different from one times 128, which is 128 not
zero.  This attack searches for the lowest power of two that is equivalent to
zero, modulo the key length.  The first power of two that is zero modulo the
key length, is the key length.

First, an arbitrary ciphertext is provided, with salt zero, except for the last
byte is 1.  The plaintext is saved as the target.  Then, for the third byte,
the values 1, 2, 4, ..., 128 are tried, until the plaintext matches the target,
indicating that the moving pointer was initialized to zero.  For keys 128 bytes
and larger, up to 32K (the max key length), the last byte of salt is set to
128, and the plaintext is saved as the target.  Then, for the third byte, the
values 1, 2, 4, ..., 128 are tried.  If the plaintext matches, then the key
length is the product of the two salt bytes (in the demonstration script, this
is two to the power of the number of tries).

In this attack, it is important that the last byte of salt remains constant.
The second salt (last four bytes) rotate to high order bits, and high bits wrap
to low.  The high bits of the salt are manipulated during the attack, and if
they rotate into the low bits, the manipulation will effect the output.
Therefore, only the high bits of the first salt are manipulated.  If a key is
built with more than 32 jumps, this attack would be ineffective, because then
even the first salt bits may have an effect on the output.

### Key Recovery: Key Jumps

The key number of jumps is supposed to be secret information.  A CCA2 attack is
provided which will recover the key number of jumps, up to 46 jumps.  This
attack could be conducted as CCA1 (batch) instead of CCA2 (adaptive), because
the attack queries do not depend on previous responses.

```
# choose a secret key
vi oracle-jumps.sh

# recover the key jumps with CCA2
./solve-jumps.py
```

The second salt rotates left every even jump (assuming jumps are numbered from
zero).  The first salt rotates right every odd jump.  When bits rotate into the
lowest byte of the respective salt, it affects the output of the cipher.  This
attack finds the bits that rotate furthest, that affect the output.  If the
second salt must be rotated 16 times to affect the output, and the first bit
must be rotated 15 times, then the key has 31 jumps.

It is important that when manipulating the first salt, the high byte of the
second salt is zero, and visa versa.  This way, the moving pointer is always
initialized to zero, even when the high bits of the other salt are changed.  If
there are enough jumps so that all of the bits in the salt affect the output,
then the attack is ineffective.

This attack is also statistically less effective against high numbers of jumps
and relatively short key lengths.  With each jump, one byte of the key body is
changed.  If that position in the key body is retrieved in a later jump, it
will effect the output.  To mitigate the effect of the changing key body, the
attack can be repeated with different values of salt, to increase the
statistical power of the attack against the effect of the changing key body.

### Plain Text Recovery

Given an encrypted message, the plain text of the message is supposed to be
secret information.  A CPA2 attack is provided which will recover the plain
text.  The CPA2 attack is not allowed to use decryption, otherwise recovering
the encrypted message would be trivial (decrypt it).  Instead, the CPA2 attack
will use information leaked by the encryption function to recover the encrypted
message.

Note: this is a CPA2 attack, and the adversary also chooses the salt.

```
# choose a secret key
vi oracle-msg.sh

# generate a random salt
S=$(../scripts/gensalt.py)
# this is your salt
echo "$S"

# encrypt the message
C=$(./oracle-msg.sh -S "$S" -M "attack at midnight")
# this is your cipher text
echo "$C"

# recover the secret message
./solve-msg.py "$S" "$C" | base64 -d; echo
```

The stream cipher generates a sequence of parity bytes which are used to
transform the plain text into cipher text by exclusive or.  The first parity
byte depends only on the key and salt, while later bytes are different
depending on the plain text.  Because the first parity byte depends only on the
key and salt, it is vulnerable to a stream cipher attack, to reveal the plain
text of the first byte.  After the first byte of plain text is known, the
stream cipher attack can be carried out against the second byte, and so on,
eventually revealing the entire message.

To decrypt a secret message M from a cipher text X, first, an arbitrary plain
text A is provided to the oracle to be encrypted as B, using the same key and
salt.  The first byte of the parity `xor(A,B)` is the same as the first byte of
the parity `xor(X,M)`.  Therefore, the first byte can be recovered as `M =
xor(X,A,B)`.  That makes this CCA2 attack a classic stream cipher attack.
Furthermore, if A is zero, then the equation can be simplified to `M =
xor(X,B)`.

After the first byte is known, the arbitrary plain text is sent with the first
known byte of plain text, and zero as the second byte.  Then the first two
known bytes of plain text, and zero as the third byte, etc, until the entire
message is revealed.

### Cipher Text Forgery

Given a plain text, only the owner of the key should be able to reliably
produce a valid cipher text that contains the message.  The CCA2 attack is
equivalent to the CPA2 plain text recovery attack, except that it uses
information leaked by the decryption function to produce a valid encrypted
message.

A separate set of attack scripts for cipher text forger are not provided.  To
perform cipher text forgery, change the operation of oracle in the plain text
recovery attack to decryption.  Then the attack becomes CCA2 cipher text
forgery.

```
# choose a secret key, change method to decrypt
vi oracle-msg.sh

# generate a random salt
S=$(../scripts/gensalt.py)
# this is your salt
echo "$S"

# encode the false secret message
M=$(echo -n "retreat at dusk" | base64)
# this is your base64 plain text
echo "$M"

# forge a ciphertext
C=$(./solve-msg.py "$S" "$M")
# this is your ciphertext
echo "$C"

# decrypt the ciphertext
T=$(./oracle-msg.sh -S "$S" -m "$C")
# this should match your base64 plain text
echo "$T"
# and this is your secret message
echo "$T" | base64 -d; echo
```
