# Java PBKDF2 #

A Java implementation of the PKCS #5 standard (Password Based Key Derivation Framework 2.0).  
This implementation allows the usage of PBKDF2 with various hash algorithms.  
For details about the standard please see [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt).


## Usage ##

```java
final String password = "password";
final int iterations = 1000;
byte[] salt;
try
{
    // Use HMAC-SHA-512 as pseudo random function
    PBKDF2 pkcs5 = new PBKDF2(PRF.HMAC_SHA512);
    // Derive the key
    byte[] key = pkcs5.deriveKey(password, iterations);
    // Store the auto generated salt in the variable "salt"
    salt = pkcs5.getSalt();
}
catch (IllegalStateException e) { }
catch (InvalidKeyException e) { }
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
