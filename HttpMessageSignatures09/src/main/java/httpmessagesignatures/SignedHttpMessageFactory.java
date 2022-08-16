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

import java.io.IOException;

import org.apache.http.HeaderIterator;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;

/**
 * Factory for creating signed requests/response.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 23.05.2022
 */
public class SignedHttpMessageFactory {

    /**
     * @param request
     * @param signatureParams
     * @return signedRequest
     */
    public static SignedHttpRequest createSignedHttpRequest(HttpRequest request, SignatureParameter signatureParams) {
        SignedHttpRequest signedRequest = new SignedHttpRequest(request.getRequestLine().getMethod(),
                request.getRequestLine().getUri(), signatureParams);

        //Add all headers of the request to be signed to the signed HTTP request.
        HeaderIterator headerIterator = request.headerIterator();
        while (headerIterator.hasNext()) {
            signedRequest.addHeader(headerIterator.nextHeader());

        }

        return signedRequest;
    }

    /**
     * In case that the request contains a message body that is included in the signature.
     * @param request
     * @param signatureParams
     * @param messageBody
     * @return signedRequest
     */
    public static SignedHttpRequest createSignedHttpRequest(HttpRequest request, SignatureParameter signatureParams,
            String messageBody) {

        SignedHttpRequest signedRequest = new SignedHttpRequest(request.getRequestLine().getMethod(),
                request.getRequestLine().getUri(), signatureParams, messageBody);

        //Add all headers of the request to be signed to the signed HTTP request.
        HeaderIterator headerIterator = request.headerIterator();
        while (headerIterator.hasNext()) {
            signedRequest.addHeader(headerIterator.nextHeader());
        }

        return signedRequest;
    }

    /**
     * This method is used to verify a request.
     * In this case, the signature parameters are extracted from the signature input header.
     * @param request
     * @return signedRequest
     */
    public static SignedHttpRequest createSignedHttpRequest(HttpRequest request) {

        SignedHttpRequest signedRequest = new SignedHttpRequest(request.getRequestLine().getMethod(),
                request.getRequestLine().getUri(), null);

        //Add all headers of the request to be signed to the signed HTTP request.
        HeaderIterator headerIterator = request.headerIterator();
        while (headerIterator.hasNext()) {
            signedRequest.addHeader(headerIterator.nextHeader());
        }

        return signedRequest;
    }

    /**
     * @param response
     * @param signatureParams
     * @param request for Request-Response Signature Binding
     * @return signedResponse
     */
    public static SignedHttpResponse createSignedHttpResponse(HttpResponse response, SignatureParameter signatureParams,
            HttpRequest request) throws IOException {
        SignedHttpResponse signedResponse;
        //Extract message body
        if (response.getEntity() != null) {
            signedResponse = new SignedHttpResponse(signatureParams, response.getStatusLine(),
                    EntityUtils.toString(response.getEntity()), request);
        } else {
            signedResponse = new SignedHttpResponse(signatureParams, response.getStatusLine(), null, request);
        }

        //Add all headers of the response to be signed to the signed HTTP response.
        HeaderIterator headerIterator = response.headerIterator();
        while (headerIterator.hasNext()) {
            signedResponse.addHeader(headerIterator.nextHeader());
        }

        return signedResponse;
    }

    /**
     * @param response
     * @param signatureParams
     * @return signedResponse
     */
    public static SignedHttpResponse createSignedHttpResponse(HttpResponse response, SignatureParameter signatureParams)
            throws IOException {
        SignedHttpResponse signedResponse;
        //Extract message body
        if (response.getEntity() != null) {
            signedResponse = new SignedHttpResponse(signatureParams, response.getStatusLine(),
                    EntityUtils.toString(response.getEntity()));
        } else {
            signedResponse = new SignedHttpResponse(signatureParams, response.getStatusLine(), null);
        }

        //Add all headers of the response to be signed to the signed HTTP response.
        HeaderIterator headerIterator = response.headerIterator();
        while (headerIterator.hasNext()) {
            signedResponse.addHeader(headerIterator.nextHeader());
        }

        return signedResponse;
    }

    /**
     * This method is used to verify a request.
     * In this case, the signature parameters are extracted from the signature input header.
     * @param response
     * @return signedResponse
     */
    public static SignedHttpResponse createSignedHttpResponse(HttpResponse response) throws IOException {
        SignedHttpResponse signedResponse;
        if (response.getEntity() != null) {
            signedResponse = new SignedHttpResponse(null, response.getStatusLine(),
                    EntityUtils.toString(response.getEntity()));
        } else {
            signedResponse = new SignedHttpResponse(null, response.getStatusLine(), null);
        }

        HeaderIterator headerIterator = response.headerIterator();
        while (headerIterator.hasNext()) {
            signedResponse.addHeader(headerIterator.nextHeader());
        }

        return signedResponse;
    }
}
