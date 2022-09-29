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

import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;

import exceptions.NoSuchSignatureException;
import signature.components.Component;
import signature.components.KeyMap;
import signature.components.SignatureParameter;
import signature.messages.SignedHttpRequest;
import signaturebase.SignaturBaseCreator;
import signaturebase.SignaturBaseCreatorRequest;

/**
 * Verifier performs the verification of a request.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 14.03.2022
 */
public class RequestVerifier extends Verifier {

    /**
     * Parse the Signature and Signature-Input fields and extract the signatures to be verified.
     * @param SignedHttpRequest to validate.
     * @param List of public keys.
     * @return Returns true, if the signature is valid.
     * @throws NoSuchSignatureException
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     * @throws InvalidAlgorithmParameterException
     */

    protected static boolean verifyRequest(SignedHttpRequest request, List<KeyMap> keys)
            throws NoSuchSignatureException, NoSuchAlgorithmException, URISyntaxException, InvalidKeyException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeySpecException {

        String host = request.getURI().getHost();
        boolean verify = false;

        // enable safe Transformation
        request = (SignedHttpRequest) transformMessage(request);

        // get Signature Labels and their Input
        Header signatureInputHeader = request.getFirstHeader("Signature-Input");
        Map<String, String> labelsAndInput = getSignatureLabelsAndInput(signatureInputHeader);
        List<String> sigLabels = new ArrayList<>();
        for (Map.Entry<String, String> entry : labelsAndInput.entrySet()) {
            String signLabel = entry.getKey();

            sigLabels.add(signLabel);

            // Section 3.2 step 2 anaylize Signatur-Input
            List<Component> coveredHeaders = getCoveredHeaders(signatureInputHeader);
            Map<String, String> signatureParameterMap = extractSignatureParameter(signatureInputHeader, signLabel);

            //Step 3 get Signature as ByteArray
            String signature = getSiganture(request, entry.getKey());

            //Step 4: Check if signature meets all requirements.
            analyzeSiganturParamater(signatureParameterMap);
            String algorithm = signatureParameterMap.get("alg");
            Long created = Long.parseLong(signatureParameterMap.get("created"));

            String nonce = signatureParameterMap.get("nonce");
            Long expires = null;
            String keyId = signatureParameterMap.get("keyid");
            SignatureParameter params;
            if (signatureParameterMap.get("expires") != null) {

                expires = Long.valueOf(signatureParameterMap.get("expires"));
                params = new SignatureParameter(algorithm, keyId, nonce, expires, signLabel, coveredHeaders);

            } else {
                params = new SignatureParameter(algorithm, keyId, nonce, signLabel, coveredHeaders);
            }
            params.setCreated(created);

            String dnsTarget = signatureParameterMap.get("dns-target");
            if (dnsTarget != null) {
                if (!isDnsTargetChanged(dnsTarget, host)) {
                    return false;
                }
                params.setDnsTarget(dnsTarget);
            }

            //Step 5: Determine the verification key material for this signature.

            byte[] publicKey = null;
            for (KeyMap keyMap : keys) {
                if (keyMap.getKeyId().equals(params.getKeyId())) {
                    publicKey = keyMap.getPublicKey();
                }
            }

            if (publicKey == null) {
                //No such key available
                throw new InvalidKeyException();
            }

            SignaturBaseCreator baseCreator = new SignaturBaseCreatorRequest(coveredHeaders, request, params);
            byte[] signatureBase = baseCreator.getSignaturebase();

            // Step 8: Verify
            verify = verify(signatureBase, signature, publicKey, params.getAlgorithm());

            //verify message body
            if (checkContentDigestIncluded(coveredHeaders)) {
                String contentDigestValue = request.getFirstHeader("content-digest").getValue();
                boolean bodyhash = verifyBody(contentDigestValue, request.getMessageBody());
                if (!bodyhash) {
                    return false;
                }

            }

        }

        return verify;

    }

    /**
     * Checks whether the dns-target matches the host.
     * @param targetIp is the IP address contained in the dns-target parameter.
     * @param host contains the hostname.
     * @return Returns true if the IP address matches the given host.
     */
    private static boolean isDnsTargetChanged(String targetIp, String host) {
        try {

            String localHostName = InetAddress.getLocalHost().getHostName();
            InetAddress[] addresses;
            //check wether host is localhost
            if ((host != null) && host.equals("localhost")) {
                addresses = InetAddress.getAllByName(host);
            } else {
                addresses = InetAddress.getAllByName(localHostName);
            }

            for (InetAddress addresse : addresses) {
                if (addresse.getHostAddress().equals(targetIp)) {
                    return true;
                }
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return false;
    }

}
