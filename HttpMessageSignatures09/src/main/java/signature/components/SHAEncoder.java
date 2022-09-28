/*
* This file is part of a Koerber Pharma Software GmbH project.
*
* Copyright (c)
*    Koerber Pharma Software GmbH
*    All rights reserved.
*
* This source file may be managed in different Java package structures,
* depending on actual usage of the source file by the Copyright holders:
*
* for Koerber:  com.werum.* or any other Werum owned Internet domain
*
* Any use of this file as part of a software system by none Copyright holders
* is subject to license terms.
*
*/
package signature.components;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Encoder hashs an input using the supported SHA functions SHA-256 and SHA-512.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 19.07.2022
 */
public class SHAEncoder {

    private SHAEncoder() {
        throw new IllegalStateException("SHAEncoder class");
    }

    /**
    * String hashed with SHA-256 hash function.
    * @param the String to be hashed.
    * @return String of the hash
    */
    public static String hash256(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.US_ASCII));
        //add colon to identify end of hash value
        return Base64.getEncoder().encodeToString(hash) + ":";
    }

    /**
     * String hashed with SHA-512 hash function.
     * @param the String to be hashed.
     * @return String of the hash
     */
    public static String hash512(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.US_ASCII));
        //add colon to identify end of hash value
        return Base64.getEncoder().encodeToString(hash) + ":";
    }
}
