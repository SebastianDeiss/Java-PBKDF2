/*
 * Copyright (c) 2015-2016, Sebastian Deiss
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package sdeiss.crypto.pkcs5;

/**
 * A main class to test PBKDF2.
 * 
 * @author Sebastian Deiss
 */
public final class Main
{
    /**
     * The Java main method.
     * 
     * @param args The command line arguments.
     */
    public static void main(String[] args)
    {
        // Test vector for HMAC-RIPEMD-160 taken from TruPax
        // https://github.com/coderslagoon/TruPax/blob/master/src/coderslagoon/tclib/crypto/PKCS5.java
        final byte[] salt = new byte[] { 0x12, 0x34, 0x56, 0x78, };
        final byte[] derivedKey = new byte[] { 0x7a, 0x3d, 0x7c, 3 };
        final String password = "password";
        int iterations = 5;

        info();

        // Run test
        try
        {
            System.out.println("=================================");
            System.out.println("Test vector");
            System.out.println("=================================");
            System.out.println("Salt        (hex): " + ByteUtil.bytesToHex(salt));
            System.out.println("Derived key (hex): " + ByteUtil.bytesToHex(derivedKey));
            System.out.println("Password:          " + password);
            System.out.println("Iterations:        " + iterations);

            PBKDF2 pkcs5 = new PBKDF2(PRF.HMAC_RIPEMD160, salt);
            final byte[] key = pkcs5.deriveKey(password, iterations, derivedKey.length);

            System.out.println("PRF:               " + pkcs5.getPRFName());
            System.out.println("=================================");
            System.out.println("Result");
            System.out.println("=================================");
            System.out.println("Derived key (hex): " + ByteUtil.bytesToHex(key));

            if (ByteUtil.arraysAreEqual(derivedKey, key))
                System.out.println("Derived key matches test vector.");
            else
                System.out.println("Derived does not match test vector.");
            System.out.println("=================================");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void info()
    {
        System.out.println("A Java implementation of the PKCS #5 standard");
        System.out.println("Password-Based Key Derivation Function 2");
        System.out.println("specified in RFC2898 (https://www.ietf.org/rfc/rfc2898.txt).");
        System.out.println("Copyright (C) 2015 Sebastian Deiss. All rights reserved.");
        System.out.println("");
    }
}
