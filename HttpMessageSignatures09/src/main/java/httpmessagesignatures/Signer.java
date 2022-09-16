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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;

import org.apache.http.HttpMessage;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import exceptions.AmbiguousSignatureLableException;

/**
 * Signer performs the signing of a HTTP message.
 * Contains the actual signature process with the provided algorithms.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 09.05.2022
 */
public abstract class Signer {

    /**
     *  Sign the signature base.
     * @param signatureBase
     * @param privateKeyMaterial
     * @param algorithm
     * @return signature as byte array
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws Exception
     */
    protected static byte[] sign(byte[] signatureBase, byte[] privateKeyMaterial, String algorithm)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException,
            InvalidKeyException, SignatureException {

        //create Key from bytes
        PrivateKey privateKey = null;
        Signature privateSignature = null;

        Security.addProvider(new BouncyCastleProvider());
        switch (algorithm) {
            case "rsa-pss-sha512":
                privateSignature = Signature.getInstance("RSASSA-PSS");
                privateSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                PKCS8EncodedKeySpec ksRSA = new PKCS8EncodedKeySpec(privateKeyMaterial);
                KeyFactory kfRSA = KeyFactory.getInstance("RSASSA-PSS");
                privateKey = kfRSA.generatePrivate(ksRSA);
                privateSignature.initSign(privateKey);
                privateSignature.update(signatureBase);
                byte[] sigRSA = privateSignature.sign();

                return sigRSA;

            case "ecdsa-p256-sha256":
                privateSignature = Signature.getInstance("SHA256withECDSA");
                PKCS8EncodedKeySpec ksECDSA = new PKCS8EncodedKeySpec(privateKeyMaterial);
                KeyFactory kfEc = KeyFactory.getInstance("EC");
                privateKey = kfEc.generatePrivate(ksECDSA);
                privateSignature.initSign(privateKey);
                privateSignature.update(signatureBase);
                byte[] sigECDSA = privateSignature.sign();

                return sigECDSA;

            case "hmac-sha256":
                HMac hMac = new HMac(new SHA256Digest());
                hMac.init(new KeyParameter(privateKeyMaterial));
                hMac.update(signatureBase, 0, signatureBase.length);
                byte[] sigHMAC = new byte[hMac.getMacSize()];
                hMac.doFinal(sigHMAC, 0);
                return sigHMAC;

            case "ed25519":
                privateSignature = Signature.getInstance("Ed25519");
                PKCS8EncodedKeySpec ksEC = new PKCS8EncodedKeySpec(privateKeyMaterial);
                KeyFactory kfEd = KeyFactory.getInstance("Ed25519");
                privateKey = kfEd.generatePrivate(ksEC);
                privateSignature.initSign(privateKey);
                privateSignature.update(signatureBase);
                byte[] sigED = privateSignature.sign();

                return sigED;

            default:
                throw new NoSuchAlgorithmException();

        }
    }

    /**
     * Signature label must be unique.
     * @param message
     * @param signLabel
     * @throws AmbiguousSignatureLableException
     */
    protected static void checkConditions(HttpMessage message, String signLabel)
            throws AmbiguousSignatureLableException {

        if (message.containsHeader("Signature-Input")
                && (message.getFirstHeader("Signature-Input").getValue().contains(" " + signLabel + "=")
                        || (message.getFirstHeader("Signature-Input").getValue().startsWith(signLabel + "=")))) {

            throw new AmbiguousSignatureLableException("Signature label must be unique.");
        }
    }

}
