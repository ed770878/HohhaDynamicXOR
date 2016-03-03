# HohhaDynamicXOR Cryptographic Analysis

This is the refactored implementation of Hohha Dynamic XOR algorithm.  An
interactive javascript demonstration of the encryption algorithm is also
available [here](https://github.com/ed770878/hohha-js).

It is [claimed to be secure][claim], but this claim is no more than a typical
real world example of [Schneier's Law][slaw].  Cryptanalysis has revealed the
algorithm to be vulnerable to a number of attacks, including complete key
recovery under a known plain text attack!

The reference implementation of the algorithm is maintained in this repository
under the branch named `reference`, where it has been extended with a test
harness and a set of unit tests.  The master branch contains a refactored
implementation of the algorithm, validated against the same set of unit tests.
The master branch also contains a number of attacks against the algorithm.  The
simple attacks are explained in the [attacks readme][attacks].  The known
plain text key recovery attack is explained below.

## Key Recovery (KPA)

In a [known plain text attack (KPA)][kpa], the adversary knows pairs of
plain text and cipher text messages, but is not given any additional
information about the key.  The most obvious challenge under KPA is to recover
the key, which would enable the attacker to perform any encryption or
decryption operation.  Alternative KPA challenges can be to decrypt novel
cipher texts without the key, or forge cipher texts without the key.  I chose
to accept the former challenge, key recovery.  Having recovered the key the
latter challenges are trivial.

A hohha key is defined by a number of jumps, and a block of initial values for
a mutable [substitution box (s-box)][sbox], called the key body.  The algorithm
is initialized by the key, and eight additional bytes of salt (the
initialization vector).  An internal value is initialized by the hohha-crc of
the key body.  An internal index into the s-box, called the moving pointer, is
initialized by just two of the bytes of salt.  As the algorithm operates,
values in the s-box are swapped with internal values, and the internal values
are xor'ed, rotated, and transformed in different ways depending on the plain
text of the message.

In simple attacks, I showed that it is possible to determine the number of
jumps, and the length of the key body.  In this attack, I assume that the
number of jumps and the length of the key body are known.  The challenge will
be to guess all of the initial values of the key body before the end of time.

We will do a depth first search of all possible combinations of bytes that
could make up the key.  If we actually search all those combinations, the
problem is intractable.  The question is, can we backtrack before making
guesses for the whole key body?  At first glance it would seem not, because one
of the initial values of the algorithm is the hohha-crc of the whole key.  But
if we guess that initial value independently rather than computing the
hohha-crc, if the search finds a solution we can just verify that the hohha-crc
matches the guessed value to accept or reject a match.  We guess values, and
backtrack as soon as the algorithm detects that it is operating differently, in
other words, if that the guessed key would produce an incorrect cipher text.

If we can backtrack at all, the next question is can we backtrack early, and
how early?  The algorithm, without an absurd number of jumps, is unlikely to be
influenced by many bytes of the key to produce the next cipher text, and after
each number of jumps there is an opportunity to backtrack when we compare the
operation to the known plain and cipher texts.  What this means is, for a
number of jumps J, we have an opportunity to backtrack after guessing at most J
bytes of the key (at most, because the same byte of the key could be referenced
by more than one jump, or it might have already been guessed).  Having the
opportunity to backtrack does not necessarily mean the search will immediately
realize it should backtrack.  It may be that a partially guessed key operates
correctly up to some number of bytes before a contradiction is discovered.

If we can backtrack early, the next question is how early.  As the depth of
backtracking can be minimized, the search time of the algorithm is reduced
exponentially.  Obviously, it makes little sense to make guesses about a key
value that is not about to be used by the algorithm, where an incorrect guess
will only result in a contradiction several steps later.  Therefore, the search
will make guesses for the next byte of the key to be used, as determined by the
moving pointer.  To increase the likelihood of finding a contradiction, many
pairs of known plain and cipher texts can be compared by running instances of
the algorithm in parallel.  The search will make guesses for the next byte of
key to be used by most of the instances.  This strategy of choosing which
variable to guess next in a constraint satisfaction problem is generally called
choosing the [most constrained variable][mcv].

If we have determined that a combination of values leads to a contradiction,
how can we avoid making the same guess again, but guessing the values in a
different order?  If it takes some number of values to find a contradiction,
then it will take that number factorial permutations of guesses to completely
rule out that combination, unless the algorithm can avoid repeating the work.
So, after choosing the most constrained variable at some step, the order of
variables is fixed thereafter, even if another variable may be more constrained
in a different branch of recursion.  The computational savings of not repeating
combinations far outweighs the effect of choosing a new most constrained
variable.

Using this constraint solver, I found that I was able to recover a 128-byte key
with two jumps in a few minutes, with one thousand known plain texts and
corresponding salt and cipher texts.  The attack can be demonstrated as
follows.

```sh
# make sure everything is built
make

# use the checked-in example, or generate a new one
cd brut
./genbrut.sh ../hohha 2 128 1000

# inspect the example:
# brut-j2-k128-t1000-key.txt - has the secret key body
# brut-j2-k128-t1000-mesg.txt - has pairs of known plain and cipher text

cd ..

# we will use only the -mesg.txt in the attack
./hohha_brut -j2 -l128 -r -f brut/brut-j2-k128-t1000-msg.txt | tee brut-log.txt

# go brew yourself a nice cup of tea while you wait a few minutes

# I recommend teeing the result to a file, like brut-log.txt as above

# if you are feeling impatient, you can monitor the process with SIGUSR1
while killall -USR1 hohha_brut; do sleep 30; done

# oh hey it's done!  see if brut-log.txt has the secret key body
```

The solution output contains:
- the guessed hohha-crc of the key body
  - this is the guess, not a computed hohha-crc!
  - even so, it should be equal to a computed hohha-crc
- the guessed values of the key body
- a mask of the key body, in case not all values are guessed
  - it is possible for a partial key to be a solution
  - add more messages, or longer messages, to constrain the solution
  - search can be restarted with the partial solution (with `-k`)

## I almost gave up

This was fun to work on for a little while.  I almost gave up working on this
project, because it is impossible to work with Mr. Kizir, the author of the
original implementation.  He does not make any attempt to understand how his
algorithm is vulnerable.  Thankfully, the spiteful comments have been removed
from [this pull request][pull13].

I only continued, because despite having to endure Mr. Kizir's insults, I am
still fascinated by cryptography.  I am by no means an expert in cryptography.
In breaking this algorithm I relied more on my experience from a college class
in artificial intelligence than any thing else, where I learned about
constraint satisfaction problems.  I took one free online course in
cryptography, but besides that I have no formal training.  I chose to work on
the hohha algorithm, because it seemed to be a relatively easy target, just the
right difficulty for someone at my level.  Having now proven, with little
doubt, that the encryption can be broken, I am glad that I did continue to work
on it after all.

## Build and test the algorithm

```
make
cd tests
./runtests.sh ../hohha
```

[claim]: https://github.com/ikizir/HohhaDynamicXOR/wiki/Reliability
[slaw]: https://www.schneier.com/blog/archives/2011/04/schneiers_law.html
[kpa]: https://en.wikipedia.org/wiki/Known-plaintext_attack
[sbox]: https://en.wikipedia.org/wiki/S-box
[pull13]: https://github.com/ikizir/HohhaDynamicXOR/pull/13
[attacks]: attacks/README.md
