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
package TestCases;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Test;

import httpmessagesignatures.Component;
import httpmessagesignatures.HttpMessageSignerFacade;
import httpmessagesignatures.KeyMap;
import httpmessagesignatures.SignatureParameter;
import httpmessagesignatures.SignedHttpMessageFactory;
import httpmessagesignatures.SignedHttpRequest;
import httpmessagesignatures.SignedHttpResponse;

/**
 * Test cases for connecting a response signature to a request. Procedure based on Draft 11.
 * https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-11
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 25.05.2022
 */
public class ReleatedResponseTest {

    @Test
    public void testReleatedResponse() throws Exception {

        HttpPost request = TestMessagProvider.getTestRequest();
        ByteArrayOutputStream messageBody = new ByteArrayOutputStream();
        request.getEntity().writeTo(messageBody);

        byte[] sharedKey = KeyProvider.getSharedSecret();

        List<Component> coveredHeadersRequest = Arrays.asList(new Component("@authority", null, false),
                new Component("content-digest", null, false));

        SignatureParameter requestParams = new SignatureParameter("hmac-sha256", "test-shared-secret", "sig-1",
                coveredHeadersRequest);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, requestParams,
                messageBody.toString());
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, sharedKey);

        List<KeyMap> listeKeys1 = new ArrayList<>();
        KeyMap map1 = new KeyMap("test-shared-secret", sharedKey);
        listeKeys1.add(map1);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys1);

        assertTrue(verify);

        List<Component> coveredHeadersResponse = Arrays.asList();
        Component[] array = coveredHeadersResponse.toArray(new Component[0]);
        coveredHeadersResponse = new ArrayList<>(Arrays.asList(array));
        coveredHeadersResponse = coveredHeadersResponse.stream().map(s -> s).collect(Collectors.toList());

        coveredHeadersResponse.add(new Component("@authority", true));
        coveredHeadersResponse.add(new Component("@query", true));
        coveredHeadersResponse.add(new Component("content-digest"));
        coveredHeadersResponse.add(new Component("@path", true));
        coveredHeadersResponse.add(new Component("@scheme", true));
        coveredHeadersResponse.add(new Component("@request-target", true));
        coveredHeadersResponse.add(new Component("@target-uri", true));
        coveredHeadersResponse.add(new Component("@method", true));
        coveredHeadersResponse.add(new Component("date", true));

        HttpResponse response = TestMessagProvider.getResponse();
        SignatureParameter responseParams = new SignatureParameter("hmac-sha256", "test-shared-secret", "sig-b24",
                coveredHeadersResponse);

        SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, responseParams,
                signedRequest);

        signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, sharedKey);
        byte[] publicKey = KeyProvider.getSharedSecret();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-shared-secret", publicKey);
        listeKeys.add(map);

        boolean verifyResponse = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);
        assertTrue(verifyResponse);

    }

    /**
     * Test of related signature binding
     * @throws Exception
     */
    @Test
    public void testRealtedSignature() throws Exception {
        //create first signature
        HttpPost request = TestMessagProvider.getTestRequest();
        ByteArrayOutputStream messageBody = new ByteArrayOutputStream();
        request.getEntity().writeTo(messageBody);

        byte[] privateKey = KeyProvider.getSharedSecret();

        List<Component> coveredHeadersRequest = Arrays.asList(new Component("@authority"),
                new Component("content-digest"));

        SignatureParameter requestParams = new SignatureParameter("hmac-sha256", "test-shared-secret", "sig-1",
                coveredHeadersRequest);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, requestParams,
                messageBody.toString());
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        List<KeyMap> listeKeys1 = new ArrayList<>();
        KeyMap map1 = new KeyMap("test-shared-secret", privateKey);
        listeKeys1.add(map1);

        boolean verify1 = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys1);

        assertTrue(verify1);
        //create second signature

        List<Component> coveredHeadersRequestSecondSig = Arrays.asList(new Component("@authority"),
                new Component("content-digest"));

        SignatureParameter requestParamsSecondSig = new SignatureParameter("hmac-sha256", "test-shared-secret", "sig-2",
                coveredHeadersRequestSecondSig);

        signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(signedRequest, requestParamsSecondSig,
                messageBody.toString());
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        boolean verifySecondSig = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys1);
        assertTrue(verifySecondSig);
        //create relatedResponse

        NameValuePair parameterSiganture = new BasicNameValuePair("key", "sig-1");

        List<Component> coveredHeadersResponse = Arrays.asList(new Component("@authority", true),
                new Component("content-digest"), new Component("signature", parameterSiganture, true));
        HttpResponse response = TestMessagProvider.getResponse();
        SignatureParameter responseParams = new SignatureParameter("hmac-sha256", "test-shared-secret", "sig-b24",
                coveredHeadersResponse);

        SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, responseParams,
                signedRequest);

        signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, privateKey);
        byte[] publicKey = KeyProvider.getSharedSecret();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-shared-secret", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);
        assertTrue(verify);

    }

}
