# HohhaDynamicXOR Cryptographic Analysis

This is the C reference implementation of Hohha Dynamic XOR algorithm.  An
interactive javascript demonstration of the encryption algorithm is also
available [here](https://github.com/ed770878/hohha-js).

It is [claimed to be secure][claim].  This is more likely just a typical real
world example of [Schneier's Law][slaw].  I invite the reader to come to her
own conclusions about the security of this algorithm.

[claim]: https://github.com/ikizir/HohhaDynamicXOR/wiki/Reliability

[slaw]: https://www.schneier.com/blog/archives/2011/04/schneiers_law.html

This repository hosts the reference implementation, a harness utility for
invoking the reference algorithm, a collection of unit tests, and a collection
of cryptographic attacks against the algorithm.  The attacks so far are pretty
simple.  Of course is the classic CCA2 stream cipher attack - that is the most
obvious.  There are two other CCA1 attacks that reveal secret information about
the key.

This was fun to work on for a little while.  I no longer plan to continue this
project.  It is impossible to work with Mr.  Kizir.  He does not make any
attempt to understand how his algorithm is vulnerable.  The typical response
is, *you obviously don't understand the algorithm well enough to see that
really it is secure*, and gems like *RSA (or, pick an algorithm) is insecure,
google doesn't use it*, interspersed with other colorful insults that,
thankfully, have been removed from [this pull request][pull13].

[pull13]: https://github.com/ikizir/HohhaDynamicXOR/pull/13

If anyone else is interested in continuing this, please, be my guest.  Here is
what to expect: unless you can demonstrate a cypher text only attack to reveal
the entire plain text, while he changes the parameters of the algorithm behind
your back, he will claim the algorithm is secure, and let loose a barrage of
insults.  You have been warned.  Good luck, and I wish you the most enduring
patience.

## Build

```
make
```

## Test

```
cd tests
./runtests.sh ../HohhaHarness
```

## Attack

See the [attacks readme](attacks/README.md).
