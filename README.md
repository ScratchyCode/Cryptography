# Cryptography
Some examples of more or less complex (not standard) cryptographic algorithms.

# Run
Simply compile in gcc (with the necessary linking options) the C sourcecode you want to test.

# Descriptions for ROT algorithms
- RANDROT.c

Encrypt/decrypt a string inserted from terminal into a file by performing bitwise rotations of the individual characters of the plain text using as shift a string of pseudo-random characters generated by a seed extrapolated from the key.


- RANDFILE.c

Encrypt/decrypt a file by performing bitwise rotations of the individual characters of the plain file using as shift a string of pseudo-random characters generated by a seed extrapolated from the key.


- SHAROT.c

Encrypt/decrypt a string inserted from terminal into a file by performing bitwise rotations of the individual characters of the plain text using as shift the values of the hash sha512 of the key. Allows to insert sentences not exceeding 64 characters (512 bits).
