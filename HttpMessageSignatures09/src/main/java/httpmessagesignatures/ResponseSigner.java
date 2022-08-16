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

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.NameValuePair;

import Exceptions.AmbiguousSignatureLableException;

/**
 * Signer performs the signing of a response.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 22.03.2022
 */
public class ResponseSigner extends Signer {

    /** List contains the identifiers of the components covered by the signature. */
    static List<Component> coveredHeaders;

    /**
     * Sign a HTTP response.
     * @param SignedHttpResponse to be signed. The response contains the parameters required for the signature.
     * @return SignedHttpResponse with attached signature.
     * @throws AmbiguousSignatureLableException
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    protected static SignedHttpResponse signResponse(SignedHttpResponse response, byte[] privateKeyMaterial)
            throws AmbiguousSignatureLableException, NoSuchAlgorithmException, URISyntaxException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidKeySpecException, SignatureException {
        HttpFieldTransformer.canonicalizeHTTPHeader(response);
        SignatureParameter signatureParameter = response.getSignatureParams();
        String signLabel = signatureParameter.getSignLabel();
        coveredHeaders = signatureParameter.getCoveredHeaders();
        extractRealtedSigantureLabels(response, coveredHeaders);

        checkConditions(response, signLabel);

        SignaturBaseCreator baseCreator = new SignaturBaseCreatorResponse(coveredHeaders, response, signatureParameter);

        byte[] signatureBase = baseCreator.getSignaturebase();
        response.setSignatureBase(new String(signatureBase, StandardCharsets.UTF_8));
        byte[] signature = sign(signatureBase, privateKeyMaterial, signatureParameter.getAlgorithm());
        String signatureStr = Base64.getEncoder().encodeToString(signature);

        //create 'Signature-Input' HTTP Field
        if (response.containsHeader("Signature-Input")) {
            Header signatureInputHeader = response.getFirstHeader("Signature-Input");
            String oldValue = signatureInputHeader.getValue();
            String newValue = oldValue + "," + "\n" + signLabel + "=" + baseCreator.signatureInput;
            response.removeHeaders("Signature-Input");
            response.addHeader("Signature-Input", newValue);
            response.setSignatureInput(newValue);
        } else {
            String signatureInputStr = signLabel + "=" + baseCreator.signatureInput;
            response.addHeader("Signature-Input", signatureInputStr);
            response.setSignatureInput(signatureInputStr);
        }

        //create 'Signature' HTTP Field
        if (response.containsHeader("Signature")) {
            Header signatureHeader = response.getFirstHeader("Signature");
            String oldValue = signatureHeader.getValue();
            String newValue = oldValue + "," + "\n" + signLabel + "=:" + signatureStr + ":";
            response.removeHeaders("Signature");
            response.addHeader("Signature", newValue);
            response.setSignature(newValue);
        } else {
            String sig = signLabel + "=:" + signatureStr + ":";
            response.addHeader("Signature", sig);
            response.setSignature(sig);
        }

        return response;
    }

    /**
    * Request-Response Signature Binding (draft 10):
    * Extract the signature label to which the signature binding refers. Change label in the coveredHeaders list.
    * These are assigned to the response to be signed.
    * @param the response to be signed
    * @return the response to be signed
    */
    private static SignedHttpResponse extractRealtedSigantureLabels(SignedHttpResponse response,
            List<Component> coveredHeaders) {

        List<String> relatedSingatureLabel = new ArrayList<>();
        //go through the list of covered components and get the signature labels from the realted signature components
        for (Component coveredHeaderName : coveredHeaders) {
            if (coveredHeaderName.isReq() && coveredHeaderName.getComponentId().equals("signature")) {
                NameValuePair[] parameters = coveredHeaderName.getParameter();
                //search for key parameter
                for (NameValuePair parameter : parameters) {
                    if (parameter.getName().equals("key")) {
                        relatedSingatureLabel.add(parameter.getValue());
                    }
                }
            }
        }

        return response;
    }

}
