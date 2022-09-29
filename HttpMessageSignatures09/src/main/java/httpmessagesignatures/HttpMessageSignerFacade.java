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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import exceptions.AmbiguousSignatureLableException;
import signature.components.KeyMap;
import signature.messages.SignedHttpRequest;
import signature.messages.SignedHttpResponse;

/**
 * Facade class for verifying and signing request and response messages.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 15.03.2022
 */
public class HttpMessageSignerFacade {

    private HttpMessageSignerFacade() {

    }

    /**
    *@return Returns signed Request.
     * @throws URISyntaxException
     * @throws AmbiguousSignatureLableException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnknownHostException
     * @throws SocketException
    */
    public static SignedHttpRequest signRequest(SignedHttpRequest request, byte[] privateKeyMaterial)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeySpecException, SignatureException, AmbiguousSignatureLableException, URISyntaxException,
            SocketException, UnknownHostException {
        return RequestSigner.signRequest(request, privateKeyMaterial);
    }

    /**
     *@return Returns signed Response.
     * @throws URISyntaxException
     * @throws AmbiguousSignatureLableException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static SignedHttpResponse signResponse(SignedHttpResponse response, byte[] privateKeyMaterial)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeySpecException, SignatureException, AmbiguousSignatureLableException, URISyntaxException,
            SocketException, UnknownHostException {
        return ResponseSigner.signResponse(response, privateKeyMaterial);
    }

    /**
     *@return Returns boolean value whether the signature on the request is valid.
     * @throws Exception
     */
    public static boolean verifyRequest(SignedHttpRequest request, List<KeyMap> keys) throws Exception {
        return RequestVerifier.verifyRequest(request, keys);
    }

    /**
     *@return Returns boolean value whether the signature on the response is valid.
     * @throws Exception
     */
    public static boolean verifyResponse(SignedHttpResponse response, List<KeyMap> keys) throws Exception {
        return ResponseVerifier.verifyResponse(response, keys);
    }
}
