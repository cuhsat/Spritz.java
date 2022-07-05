# Spritz.java
A Spritz cipher implementation in pure Java 18.

Spritz is a RC4 redesign by *Ron Rivest* and *Jacob Schuldt*
[(PDF)](doc/RS14.pdf).

# Exports

## Encryption
* `void Spritz.encrypt(short[] text, short[] key)`
* `void Spritz.encrypt(short[] text, short[] key, short[] iv)`

## Decryption
* `void Spritz.decrypt(short[] text, short[] key)`
* `void Spritz.decrypt(short[] text, short[] key, short[] iv)`

## Hash
* `void Spritz.hash(short[] message, short[] digest)`

## MAC 
* `void Spritz.mac(short[] message, short[], key, short[] code)`

# License
Release into the [Public Domain](LICENSE.txt).