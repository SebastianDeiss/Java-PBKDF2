/*
 * Copyright (c) 2015, Sebastian Deiss
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package sdeiss.crypto.pkcs5;

/**
 * A byte conversion utility.
 * 
 * @author Sebastian Deiss
 * @version 1.0
 */
public final class ByteUtil
{
	/**
	 * Convert a byte array to a String of hex characters.
	 * 
	 * @param bytes The byte array to convert
	 * @return A hex string
	 */
	public static final String bytesToHex(final byte[] bytes)
	{
		if (bytes == null)
			return null;
		else
		{
			int length = bytes.length;
			String hexBytes = "";
			for (int i = 0; i < length; i++)
			{
				if ((bytes[i] & 0xFF) < 16)
				{
					hexBytes += "0";
					hexBytes += Integer.toHexString(bytes[i] & 0xFF);
				}
				else
					hexBytes += Integer.toHexString(bytes[i] & 0xFF);
			}
			
			return hexBytes;
		}
	}
	
	/**
	 * Convert a String of hex characters to a byte array.
	 * 
	 * @param hexBytes The string to convert
	 * @return A byte array
	 */
	public static final byte[] hexToBytes(final String hexBytes)
	{
		if (hexBytes == null | hexBytes.length() < 2)
			return null;
		else
		{
			int length = hexBytes.length() / 2;
			byte[] buffer = new byte[length];
			for (int i = 0; i < length; i++)
				buffer[i] = (byte) Integer.parseInt(hexBytes.substring(i * 2, i * 2 + 2), 16);
			
			return buffer;
		}
	}
	
	/**
	 * Convert a byte size into a human readable format.
	 * 1024 bytes  = 1 KB
	 * 1024 * 1024 = 1 MB
	 * ...
	 * 
	 * @param bytes The byte size to convert.
	 * @return Returns the given byte size in a human readable format
	 */
	public static final String humanReadableByteCount(final long bytes)
	{
	    final int unit = 1024;
	    if (bytes < unit)
	    	return bytes + " B";
	    
	    int exp = (int) (Math.log(bytes) / Math.log(unit));
	    String pre = ("KMGTPE").charAt(exp-1) + ("");
	    return String.format("%.1f %sB", bytes / Math.pow(unit, exp), pre);
	}
	
	/**
	 * Check if two byte arrays are equal.
	 * 
	 * @param array1 The first array
	 * @param array2 the second array
	 * @return Returns true if the arrays are equal otherwise false
	 */
	public static final boolean arraysAreEqual(final byte[] array1, final byte[] array2)
	{
	    if (array1.length != array2.length)
		return false;
	    
	    for (int i = 0; i < array1.length; i++)
	    {
		if (array1[i] != array2[i])
		    return false;
	    }
	    
	    return true;
	}
	
	/**
	 * Convert a big-endian byte array into a 32-bit integer value.
	 * 
	 * @param bytes The byte array to convert
	 * @param offset The offset inside the array
	 * @return Returns a 16-bit integer value representing the byte array
	 */
	public final static short loadInt16BE(byte[] bytes, int offset)
	{
	    return (short)(((bytes[offset    ] & 0xff) << 8) |
	    				(bytes[offset + 1] & 0xff));
	}
	
	/**
	 * Convert a little-endian byte array into a 32-bit integer value
	 * 
	 * @param bytes The byte array to convert
	 * @param offSet The offset inside the array
	 * @return Returns a 32-bit integer value representing the byte array
	 */
	public final static int loadInt32LE(final byte[] bytes, int offSet)
	{
	    return ( bytes[offSet + 3]         << 24) |
	    	   ((bytes[offSet + 2] & 0xff) << 16) |
	    	   ((bytes[offSet + 1] & 0xff) <<  8) |
	    	    (bytes[offSet    ] & 0xff);
	}
	
	/**
	 * Convert a big-endian byte array into a 32-bit integer value
	 * 
	 * @param bytes The byte array to convert
	 * @param offSet The offset inside the array
	 * @return Returns a 32-bit integer value representing the byte array
	 */
	public final static int loadInt32BE(byte[] bytes, int offSet)
	{
	    return ( bytes[offSet     ]         << 24) |
		       ((bytes[offSet + 1] & 0xff) << 16) |
		       ((bytes[offSet + 2] & 0xff) <<  8) |
		        (bytes[offSet + 3] & 0xff);
	}
	
	/**
	 * Convert a little-endian byte array into a 64-bit integer value (long)
	 * 
	 * @param bytes The byte array to convert
	 * @param offSet The offset inside the array
	 * @return Returns a 64-bit integer value representing the byte array
	 */
	public final static long loadInt64LE(final byte[] bytes, int offSet)
	{
	    return (      loadInt32LE(bytes, offSet    ) & 0x0ffffffffL) |
	    	   ((long)loadInt32LE(bytes, offSet + 4) << 32);
	}
	
	/**
	 * Convert a big-endian byte array into a 64-bit integer value (long)
	 * 
	 * @param bytes The byte array to convert
	 * @param offSet The offset inside the array
	 * @return Returns a 64-bit integer value representing the byte array
	 */
	public final static long loadInt64BE(byte[] bytes, int offSet)
	{
	    return (      loadInt32BE(bytes, offSet + 4) & 0x0ffffffffL) |
	    	   ((long)loadInt32BE(bytes, offSet    ) << 32);
	}
	
	/**
	 * Convert a 32-bit integer value into a little-endian byte array
	 * 
	 * @param value The integer to convert
	 * @param bytes The byte array to store the converted value
	 * @param offSet The offset in the output byte array
	 */
	public final static void storeInt32LE(int value, byte[] bytes, int offSet)
	{
		bytes[offSet    ] = (byte)(value       );
		bytes[offSet + 1] = (byte)(value >>>  8);
		bytes[offSet + 2] = (byte)(value >>> 16);
		bytes[offSet + 3] = (byte)(value >>> 24);
	}
	
	/**
	 * Convert a 32-bit integer value into a big-endian byte array
	 * 
	 * @param value The integer value to convert
	 * @param bytes The byte array to store the converted value
	 * @param offSet The offset in the output byte array
	 */
	public final static void storeInt32BE(int value, byte[] bytes, int offSet)
	{
		bytes[offSet + 3] = (byte)(value       );
		bytes[offSet + 2] = (byte)(value >>>  8);
		bytes[offSet + 1] = (byte)(value >>> 16);
		bytes[offSet    ] = (byte)(value >>> 24);
	}
	
	/**
	 * Convert a 64-bit integer value (long) into a little-endian byte array
	 * 
	 * @param value The long value to convert
	 * @param bytes The byte array to store the converted value
	 * @param offSet The offset in the output byte array
	 */
	public final static void storeInt64LE(long value, byte[] bytes, int offSet)
	{
	    storeInt32LE((int)(value >>> 32), bytes, offSet + 4);
	    storeInt32LE((int)(value       ), bytes, offSet);
	}
}
