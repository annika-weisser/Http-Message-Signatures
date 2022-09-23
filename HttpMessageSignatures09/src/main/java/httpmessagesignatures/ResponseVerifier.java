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

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;

/**
 * Verifier performs the verification of a response.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 22.03.2022
 */
public class ResponseVerifier extends Verifier {

    /** List contains the identifiers of the components covered by the signature. */
    static List<Component> coveredHeaders;

    /**
     * Parse the Signature and Signature-Input fields and extract the signatures to be verified.
     * @param SignedHttpResponse to validate.
     * @param List of public keys.
     * @return Returns true, if the signature is valid.
     * @throws Exception
     */
    protected static boolean verifyResponse(SignedHttpResponse response, List<KeyMap> keys) throws Exception {
        boolean verify = false;

        // enable safe Transformation
        response = (SignedHttpResponse) transformMessage(response);
        Header signatureInputHeader = response.getFirstHeader("Signature-Input");

        // get Signature Labels and their Input
        Map<String, String> labelsAndInput = getSignatureLabelsAndInput(signatureInputHeader);
        List<String> sigLabels = new ArrayList<>();
        for (Map.Entry<String, String> entry : labelsAndInput.entrySet()) {
            String signLabel = entry.getKey();
            sigLabels.add(signLabel);

            // Section 3.2 step 2 anaylize Signatur-Input
            coveredHeaders = getCoveredHeaders(signatureInputHeader, signLabel);
            Map<String, String> signatureParameterMap = extractSignatureParameter(signatureInputHeader, signLabel);

            // get Signature as ByteArray
            String signature = getSiganture(response, entry.getKey());

            // Check if signature meets all requirements.
            analyzeSiganturParamater(signatureParameterMap);
            String algorithm = signatureParameterMap.get("alg");
            Long created = Long.parseLong(signatureParameterMap.get("created"));
            String nonce = signatureParameterMap.get("nonce");
            String keyId = signatureParameterMap.get("keyid");

            SignatureParameter params;
            if (signatureParameterMap.get("expires") != null) {

                Long expires = Long.valueOf(signatureParameterMap.get("expires"));
                params = new SignatureParameter(algorithm, keyId, nonce, created, expires, signLabel, coveredHeaders);

            } else {
                params = new SignatureParameter(algorithm, keyId, nonce, created, signLabel, coveredHeaders);
            }

            //Determine the verification key material for this signature.
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

            SignaturBaseCreator baseCreator = new SignaturBaseCreatorResponse(coveredHeaders, response, params);
            byte[] signatureBase = baseCreator.getSignaturebase();

            // Step 8: Verify
            verify = verify(signatureBase, signature, publicKey, params.getAlgorithm());

            //verify message body
            if (checkContentDigestIncluded(coveredHeaders)) {
                String contentDigestValue = response.getFirstHeader("content-digest").getValue();
                boolean bodyhash = verifyBody(contentDigestValue, response.getMessageBody());
                if (!bodyhash) {
                    return false;
                }
            }

        }

        return verify;
    }

}
