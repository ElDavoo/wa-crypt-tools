package com.test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/*
The original loop WhatsApp uses to encode a encrypted_backup.key.
TODO make a python implementation of this function.
 */
public class WA_HMACSHA256_Loop {

    public static byte[] nestedHMACSHA256NoKey(byte[] first_iteration_data, byte[] message, int permutations) {
        return nestedHmacSHA256(first_iteration_data, new byte[32], message, permutations);
    }
    public static byte[] nestedHmacSHA256(byte[] first_iteration_data, byte[] privateHmacSHA256Key, byte[] message, int permutations) {
        try {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            hmacSHA256.init(new SecretKeySpec(privateHmacSHA256Key, "HmacSHA256"));
            byte[] hmacsha256header = hmacSHA256.doFinal(first_iteration_data);
            try {
                /*The permutation number is actually divided by 32.
                Be sure to give *32 the number of permutations you actually want!*/
                int numPermutations = (int) Math.ceil(((double) permutations) / 32.0d);
                byte[] existingData = new byte[0];
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                for (int i = 1; i < numPermutations + 1; i++) {
                    Mac hasher = Mac.getInstance("HmacSHA256");
                    hasher.init(new SecretKeySpec(hmacsha256header, "HmacSHA256"));
                    hasher.update(existingData);
                    if (message != null) {
                        hasher.update(message);
                    }
                    // Mettiamoci dentro anche l'indice
                    byte one = (byte) i;
                    System.out.println((byte) i);
                    hasher.update((byte) i);
                    existingData = hasher.doFinal();
                    int min = Math.min(permutations, existingData.length);
                    byteArrayOutputStream.write(existingData, 0, min);
                    permutations -= min;
                }
                return byteArrayOutputStream.toByteArray();
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                throw new AssertionError(e);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e2) {
            throw new AssertionError(e2);
        }
    }
}
