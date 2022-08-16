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
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpMessage;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicHeader;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Exceptions.NoSuchSignatureException;

/**
 * Verifier performs the verification of a HTTP message.
 * Includes the actual verification with the provided algorithms.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 10.05.2022
 */
public abstract class Verifier {

    protected static List<String> supportedSignatureAlgorithms = Arrays.asList("RSASSA-PSS", "ecdsa-p256-sha256",
            "hmac-sha256", "ed25519");

    /**
     * @param signatureBase
     * @param publicKey
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     */
    protected static boolean verify(byte[] signatureBase, String signature, byte[] publicKeyMaterial, String algorithm)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, InvalidKeySpecException {
        PublicKey publicKey;
        Signature publicSignature;
        Security.addProvider(new BouncyCastleProvider());

        switch (algorithm) {
            case "rsa-pss-sha512":

                publicSignature = Signature.getInstance("RSASSA-PSS");
                publicSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                KeyFactory kfRSA = KeyFactory.getInstance("RSASSA-PSS");
                X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyMaterial);
                publicKey = kfRSA.generatePublic(ks);
                publicSignature.initVerify(publicKey);
                publicSignature.update(signatureBase);

                byte[] signatureBytesRSAPSS = Base64.getDecoder().decode(signature);
                boolean verifyRSA = publicSignature.verify(signatureBytesRSAPSS);

                return verifyRSA;

            case "ecdsa-p256-sha256":

                publicSignature = Signature.getInstance("SHA256withECDSA");
                X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyMaterial);
                KeyFactory kfEc = KeyFactory.getInstance("EC");
                publicKey = kfEc.generatePublic(spec);
                publicSignature.initVerify(publicKey);
                publicSignature.update(signatureBase);

                byte[] signatureBytesEC = Base64.getDecoder().decode(signature);
                boolean verifyECDSA = publicSignature.verify(signatureBytesEC);

                return verifyECDSA;

            case "hmac-sha256":
                HMac hMac = new HMac(new SHA256Digest());
                hMac.init(new KeyParameter(publicKeyMaterial));
                hMac.update(signatureBase, 0, signatureBase.length);

                byte[] newSignature = new byte[hMac.getMacSize()];
                hMac.doFinal(newSignature, 0);
                byte[] originSignature = Base64.getDecoder().decode(signature);
                boolean verifyHMAC = Arrays.equals(originSignature, newSignature);
                return verifyHMAC;

            case "ed25519":
                publicSignature = Signature.getInstance("Ed25519");
                X509EncodedKeySpec ksEd = new X509EncodedKeySpec(publicKeyMaterial);
                KeyFactory kfEd = KeyFactory.getInstance("Ed25519");
                publicKey = kfEd.generatePublic(ksEd);
                publicSignature.initVerify(publicKey);
                publicSignature.update(signatureBase);

                byte[] signatureBytesEd = Base64.getDecoder().decode(signature);
                boolean verifyED = publicSignature.verify(signatureBytesEd);

                return verifyED;

            default:
                return false;

        }

    }

    /**
     *
     * @param signatureParameter
     * @return
     * @throws Exception
     */
    protected static boolean analyzeSiganturParamater(Map<String, String> signatureParameter) {

        //If an expired field is included, check if the signature has expired
        if (signatureParameter.containsKey("expires")) {
            long expires = Long.valueOf(signatureParameter.get("expires"));
            if (Instant.now().getEpochSecond() > expires) {
                return false;
            }
        }

        //check whether the signature algorithm used is supported
        if (!(supportedSignatureAlgorithms.contains(signatureParameter.get("algorithm")))) {
            return false;
        }
        return true;

    }

    /**
     * extract Signature-Labels
     * @return Returns the signature label along with its signature-input.
     */
    protected static Map<String, String> getSignatureLabelsAndInput(Header header) {

        Map<String, String> labelsAndInput = new HashMap<>();
        HeaderElement[] sigInput = header.getElements();
        for (HeaderElement element : sigInput) {
            String sigLabel = element.getName();
            String signatureInput = element.getValue();
            NameValuePair[] parameters = element.getParameters();

            for (NameValuePair param : parameters) {
                signatureInput = signatureInput + ";" + param;
            }
            labelsAndInput.put(sigLabel, signatureInput);
        }

        return labelsAndInput;
    }

    /**
     *extract signature parameters
     * @param signLabel
     * @return Returns extracted signature parameter.
     */
    protected static Map<String, String> extractSignatureParameter(Header entry, String signatureLabel) {

        Map<String, String> signatureParameter = new HashMap<>();
        HeaderElement[] signaturElements = entry.getElements();

        for (HeaderElement element : signaturElements) {
            if (element.getName().equals(signatureLabel)) {
                NameValuePair[] parameters = element.getParameters();

                for (NameValuePair param : parameters) {
                    if (!param.getName().startsWith("req")) {
                        signatureParameter.put(param.getName(), param.getValue());
                    }

                }
            }

        }
        return signatureParameter;

    }

    /**
     *
     * @param message
     * @param signatureLabel
     * @return Signature as String
     * @throws NoSuchSignatureException
     */
    protected static String getSiganture(HttpMessage message, String signatureLabel) throws NoSuchSignatureException {

        Header signatureHeader = message.getFirstHeader("Signature");
        HeaderElement[] signaturElements = signatureHeader.getElements();

        for (HeaderElement element : signaturElements) {
            if (element.getName().equals(signatureLabel)) {
                String signature = element.getValue();
                signature = signature.substring(1, signature.length() - 1);
                return signature;
            }
        }
        //if the signature label does not refer to an existing signature
        throw new NoSuchSignatureException("No signature found for the label " + signatureLabel);

    }

    /**
     *
     * @param message
     * @return message with transformed header field names
     */
    protected static HttpMessage transformMessage(HttpMessage message) {
        message = HttpFieldTransformer.canonicalizeHTTPHeader(message);
        return message;
    }

    /**
     *
     * @param contentDigestValue
     * @param messageBody
     * @return Returns true if the hash value of the message body is valid.
     * @throws NoSuchAlgorithmException
     */
    protected static boolean verifyBody(String contentDigestValue, String messageBody) throws NoSuchAlgorithmException {
        //determination hash function
        int endPos = contentDigestValue.indexOf("=");
        String sha = contentDigestValue.substring(0, endPos);
        String bodyHash;
        switch (sha) {
            case "sha-256":
                bodyHash = SHAEncoder.hash256(messageBody);
                break;
            case "sha-512":
                bodyHash = SHAEncoder.hash512(messageBody);
                break;
            default:
                throw new NoSuchAlgorithmException();
        }

        //remove prefix
        contentDigestValue = contentDigestValue.substring(9);
        return contentDigestValue.equals(bodyHash);

    }

    /**
     * Extract the ids of the covered components from the signature input header.
     * @param signatureInput
     * @param signatureLabel
     * @return List of coveredHeaders.
     */
    protected static List<Component> getCoveredHeaders(Header signatureInput, String signatureLabel) {
        List<Component> coveredHeaders = new ArrayList<>();

        String value = signatureInput.getValue();
        int startPos = value.indexOf("(") + 1;
        int endPos = value.indexOf(")");
        value = value.substring(startPos, endPos);
        value = value.replaceAll("\"", "");
        value = value.replace(" ", ", ");
        coveredHeaders = extractComponent(value.toLowerCase(), coveredHeaders);

        return coveredHeaders;
    }

    /**
     * Get the components from the inner list of the signature input
     * @param value
     */
    private static List<Component> extractComponent(String value, List<Component> coveredHeaders) {

        Header extractHeader = new BasicHeader("", value);
        HeaderElement[] elements = extractHeader.getElements();

        for (HeaderElement element : elements) {
            String componentId = null;
            NameValuePair[] parameters = null;
            NameValuePair parameter = null;
            boolean req = false;
            componentId = element.getName();
            parameters = element.getParameters();

            //check if req parameter is included
            for (NameValuePair nameValuePair : parameters) {
                if (nameValuePair.getName().equals("req")) {
                    req = true;
                } else {
                    parameter = nameValuePair;
                }
            }

            coveredHeaders.add(new Component(componentId, parameter, req));
        }
        return coveredHeaders;

    }

    /**
     * @return boolean if coveredHeaders contains content-digest header
     */
    protected static boolean checkContentDigestIncluded(List<Component> coveredHeaders) {
        boolean contains = false;
        Iterator<Component> iterator = coveredHeaders.iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getComponentId().equals("content-digest")) {
                contains = true;
            }
        }

        return contains;
    }

}
