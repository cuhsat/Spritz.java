# Spritz.java
A `Spritz` cipher implementation in pure Java 11.

Spritz is a RC4 redesign by *Ron Rivest* and *Jacob Schuldt*
[(PDF)](doc/RS14.pdf).

# Exports
* `void Spritz.encrypt(short[] text, short[] key)`
* `void Spritz.decrypt(short[] text, short[] key)`
* `void Spritz.hash(short[] message, short[] digest)`

# License
Release into the [Public Domain](LICENSE.txt).