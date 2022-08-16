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
package httpmessagesignatures;

/**
 * KeyMap Class for storing various public keys for verifying an HTTP message.
 * Each public key can be assigned an id.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 14.03.2022
 */
public class KeyMap {

    /** ID of the public key. */
    private String keyId;
    /** Public key as a byte array. */
    private byte[] publicKey;

    /**
     * Constructor.
     * @param keyId
     * @param publicKey
     */
    public KeyMap(String keyId, byte[] publicKey) {

        this.keyId = keyId;
        this.publicKey = publicKey;

    }

    /**
     * @return the keyId
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * @param keyId the keyId to set
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * @return the public key
     */
    public byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * @param publicKey the public key to set
     */
    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

}
