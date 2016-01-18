# Java PBKDF2 #

A Java implementation of the PKCS #5 standard (Password-Based Key Derivation Function 2).  
This implementation allows the usage of PBKDF2 with various hash algorithms.  
For details about the standard please see [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt).


## Examples ##

### Derive a key with a random generated salt ###

**Note:** The length of the derived key will be the same as the output size of the underlying PRF.

```java
final String password = "password";
final int iterations = 1000;
byte[] derivedKey;
byte[] salt;
try
{
    // Use HMAC-SHA-512 as pseudo random function
    PBKDF2 pkcs5 = new PBKDF2(PRF.HMAC_SHA512);
    // Derive a key
    derivedKey = pkcs5.deriveKey(password, iterations);
    // Store the auto generated random salt in the variable "salt"
    salt = pkcs5.getSalt();
}
catch (IllegalStateException e) {}
catch (InvalidKeyException e)   {}
```

### Derive a key with a specific salt and key length ###

```java
final String password = "password";
final int iterations = 1000;
final int keyLength = 32;
byte[] derivedKey;
byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xA};
try
{
    // Use HMAC-SHA-512 as pseudo random function and a specific salt
    PBKDF2 pkcs5 = new PBKDF2(PRF.HMAC_SHA512, salt);
    // Derive a key with a specific length
    derivedKey = pkcs5.deriveKey(password, iterations, keyLength);
}
catch (IllegalStateException e) {}
catch (InvalidKeyException e)   {}
```

## License ##
This software is released under the BSD 2-Clause License.  
For details see [License.txt](./License.txt).


## Supported Hash Algorithms ##
* RIPEMD-160
* SHA-256
* SHA-512
* Whirlpool 


## Dependencies ##
None. It includes the required parts of Bouncy Castle.
