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

import java.net.SocketException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;

import org.apache.http.Header;

import exceptions.AmbiguousSignatureLableException;

/**
 * Signer performs the signing of a request.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 08.03.2022
 */
public class RequestSigner extends Signer {

    /**
     * Sign a HTTP request.
     * @param request
     * @param privateKeyMaterial to be signed. The request contains the parameters required for the signature.
     * @return SignedHttpRequest with attached signature.
     * @throws AmbiguousSignatureLableException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     */
    protected static SignedHttpRequest signRequest(SignedHttpRequest request, byte[] privateKeyMaterial)
            throws AmbiguousSignatureLableException, NoSuchAlgorithmException, URISyntaxException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidKeySpecException, SignatureException, SocketException,
            UnknownHostException {

        HttpFieldTransformer.canonicalizeHTTPHeader(request);
        SignatureParameter signatureParameter = request.getSignatureParams();
        String signLabel = signatureParameter.getSignLabel();
        List<Component> coveredHeaders = signatureParameter.getCoveredHeaders();

        checkConditions(request, signLabel);

        SignaturBaseCreator baseCreator = new SignaturBaseCreatorRequest(coveredHeaders, request, signatureParameter);

        byte[] signatureBase = baseCreator.getSignaturebase();
        request.setSignatureBase(new String(signatureBase, StandardCharsets.UTF_8));
        byte[] signature = sign(signatureBase, privateKeyMaterial, signatureParameter.getAlgorithm());
        String signatureStr = Base64.getEncoder().encodeToString(signature);

        //create 'Signature-Input' HTTP Field
        if (request.containsHeader("Signature-Input")) {
            Header signatureInputHeader = request.getFirstHeader("Signature-Input");
            String oldValue = signatureInputHeader.getValue();
            String newValue = oldValue + "," + "\n" + signLabel + "= " + baseCreator.signatureInput;
            request.removeHeaders("Signature-Input");
            request.addHeader("Signature-Input", newValue);
            request.setSignatureInput(newValue);
        } else {
            request.addHeader("Signature-Input", signLabel + "=" + baseCreator.signatureInput);
        }

        //create 'Signature' HTTP Field
        if (request.containsHeader("Signature")) {
            Header signatureHeader = request.getFirstHeader("Signature");
            String oldValue = signatureHeader.getValue();

            String newValue = oldValue + "," + "\n" + signLabel + "=:" + signatureStr + ":";
            request.removeHeaders("Signature");
            request.addHeader("Signature", newValue);

        } else {
            request.addHeader("Signature", signLabel + "=:" + signatureStr + ":");
        }

        return request;
    }

}
