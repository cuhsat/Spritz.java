# Spritz.java
A Spritz cipher implementation in pure Java.

Spritz is a RC4 redesign by *Ron Rivest* and *Jacob Schuldt*
[(PDF)](doc/RS14.pdf).

# Exports

## Encryption
* `Spritz.encrypt(text, key)`
* `Spritz.encrypt(text, key, iv)`

## Decryption
* `Spritz.decrypt(text, key)`
* `Spritz.decrypt(text, key, iv)`

## Hash
* `Spritz.hash(message, digest)`

## MAC 
* `Spritz.mac(message, key, code)`

## PRNG
* `Spritz.random()`
* `Spritz.randomSeed(seed)`

# License
Release into the [Public Domain](LICENSE.txt).
