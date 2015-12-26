/*
 * Copyright (c) 2015, Sebastian Deiss
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

import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;

/**
 * PKCS #5 Password Based Key Derivation Framework 2.0 (PBKDF2).
 * 
 * @author Sebastian Deiss
 * @see <a href="https://www.ietf.org/rfc/rfc2898.txt">RFC 2898</a>
 * 
 */
public final class PBKDF2
{
    private final HMac PRF;
    private byte[] salt;
    private final int hLen;

    /**
     * Initialize PBKDF2.
     * 
     * @param prf The name of the hash algorithm to use with HMAC as PRF.
     * @throws IllegalStateException If the supplied hash algorithm name does
     *         not match any supported hash algorithm.
     */
    public PBKDF2(final PRF prf) throws IllegalStateException
    {
        switch (prf)
        {
            case HMAC_SHA256:
                this.PRF = new HMac(new SHA256Digest());
                break;
            case HMAC_SHA512:
                this.PRF = new HMac(new SHA512Digest());
                break;
            case HMAC_RIPEMD160:
                this.PRF = new HMac(new RIPEMD160Digest());
                break;
            case HMAC_Whirlpool:
                this.PRF = new HMac(new WhirlpoolDigest());
                break;
            default:
                throw new IllegalStateException();
        }

        this.hLen = this.PRF.getMacSize();
        this.salt = new byte[this.PRF.getMacSize()];

        // Generate a salt
        new SecureRandom().nextBytes(salt);
    }

    /**
     * Initialize PBKDF2 with a specified salt.
     * 
     * @param prf The name of the hash algorithm to use with HMAC as PRF.
     * @param salt The salt to use.
     * @throws IllegalStateException If the supplied hash algorithm name does
     *         not match any supported hash algorithm.
     */
    public PBKDF2(final PRF prf, final byte[] salt) throws IllegalStateException
    {
        this(prf);
        this.salt = salt;
    }

    /**
     * Get the PRF name.
     * 
     * @return The name of the PRF as string.
     */
    public final String getPRFName()
    {
        return this.PRF.getAlgorithmName();
    }

    /**
     * Get the length of the output of the PRF.
     * 
     * @return The length of the PRF output.
     */
    public final int getPRFSize()
    {
        return this.PRF.getMacSize();
    }

    /**
     * Get the salt used to derive the key.
     * 
     * @return The salt used to derive the key.
     */
    public final byte[] getSalt()
    {
        return this.salt;
    }

    /**
     * Get the length of the salt.
     * 
     * @return The length of the salt used for key derivation. By default the
     *         salt length is equal to getPRFSize.
     */
    public final int getSaltSize()
    {
        return this.salt.length;
    }

    /**
     * Derive a key.
     * 
     * @param password The password to derive the key from.
     * @param iterations The iteration count.
     * @return Returns a key derived with the specified parameters.
     * @throws InvalidKeyException If the specified length for the derived key
     *         is to long.
     */
    public final byte[] deriveKey(final String password, final int iterations) throws InvalidKeyException
    {
        return this.deriveKey(password, iterations, this.hLen);
    }

    /**
     * Derive a key with a specified length.
     * 
     * @param password The password to derive the key from.
     * @param iterations The iteration count.
     * @param dkLen The length of the derived key.
     * @return Returns a key derived with the specified parameters.
     * @throws InvalidKeyException If the specified length for the derived key
     *         is to long.
     */
    public final byte[] deriveKey(final String password, final int iterations, final int dkLen) throws InvalidKeyException
    {
        // Check key length
        if (dkLen > ((Math.pow(2, 32) - 1) * this.hLen))
            throw new InvalidKeyException("Derived key to long");

        byte[] derivedKey = new byte[dkLen];

        final int J = 0;
        final int K = this.PRF.getMacSize();
        final int U = this.PRF.getMacSize() << 1;
        final int B = K + U;
        final byte[] workingArray = new byte[K + U + 4];

        // Initialize PRF
        CipherParameters macParams = new KeyParameter(password.getBytes());
        this.PRF.init(macParams);

        // Perform iterations
        for (int kpos = 0, blk = 1; kpos < dkLen; kpos += K, blk++)
        {
            ByteUtil.storeInt32BE(blk, workingArray, B);

            this.PRF.update(this.salt, 0, salt.length);

            this.PRF.reset();
            this.PRF.update(salt, 0, salt.length);
            this.PRF.update(workingArray, B, 4);
            this.PRF.doFinal(workingArray, U);
            System.arraycopy(workingArray, U, workingArray, J, K);

            for (int i = 1, j = J, k = K; i < iterations; i++)
            {
                this.PRF.init(macParams);
                this.PRF.update(workingArray, j, K);
                this.PRF.doFinal(workingArray, k);

                for (int u = U, v = k; u < B; u++, v++)
                    workingArray[u] ^= workingArray[v];

                int swp = k;
                k = j;
                j = swp;
            }

            int tocpy = Math.min(dkLen - kpos, K);
            System.arraycopy(workingArray, U, derivedKey, kpos, tocpy);
        }

        Arrays.fill(workingArray, (byte) 0);

        return derivedKey;
    }

    @Override
    protected void finalize() throws Throwable
    {
        super.finalize();
        Arrays.fill(this.salt, (byte) 0);
    }
}
