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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import httpmessagesignatures.HttpMessageSignerFacade;
import httpmessagesignatures.SignedHttpMessageFactory;
import signature.components.Component;
import signature.components.KeyMap;
import signature.components.SHAEncoder;
import signature.components.SignatureParameter;
import signature.messages.SignedHttpRequest;
import signature.messages.SignedHttpResponse;

/**
 * Test cases for signing the message body (based on draft 10).
 * https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-10
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 19.07.2022
 */
public class TestMessageBody {

    @Test
    public void testSHA256() throws Exception {
        String body = "{\"hello\": \"world\"}";
        String hash = SHAEncoder.hash256(body);
        assertEquals("X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", hash);

    }

    @Test
    public void testSHA512() throws Exception {
        String body = "{\"hello\": \"world\"}";
        String hash = SHAEncoder.hash512(body);
        assertEquals("WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:", hash);

    }

    @Test
    public void testSHA512Dog() throws Exception {
        String body = "{\"hello\": \"world\"}";
        String hash = SHAEncoder.hash512(body);
        assertEquals("WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:", hash);

    }

    @Test
    public void testoriginMessageBody() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getPrivateEccKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("Content-Digest"));

        SignatureParameter params = new SignatureParameter("ecdsa-p256-sha256", "test-key-ecc-p256", "sig-b22",
                coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        byte[] publicKey = KeyProvider.getPublicEccKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-ecc-p256", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);

        assertTrue(verify);

    }

    @Test
    public void testChangeMessageBody() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getPrivateEccKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("Content-Digest"));

        SignatureParameter params = new SignatureParameter("ecdsa-p256-sha256", "test-key-ecc-p256", "sig-b22",
                coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);
        signedRequest.setMessageBody("{\"bye\": \"world\"}");

        byte[] publicKey = KeyProvider.getPublicEccKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-ecc-p256", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);

        assertFalse(verify);
    }

    //
    @Test
    public void testoriginResponseBody() throws Exception {
        HttpResponse response = TestMessagProvider.getResponse();
        byte[] privateKey = KeyProvider.getPrivateEccKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("content-digest"));

        SignatureParameter params = new SignatureParameter("ecdsa-p256-sha256", "test-key-ecc-p256", "sig-b22",
                coveredHeaders);

        SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, params);
        signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, privateKey);

        byte[] publicKey = KeyProvider.getPublicEccKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-ecc-p256", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);

        assertTrue(verify);
    }

    @Test
    public void testChangeResponseBody() throws Exception {
        HttpResponse response = TestMessagProvider.getResponse();
        byte[] privateKey = KeyProvider.getPrivateEccKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@status"), new Component("content-digest"));

        SignatureParameter params = new SignatureParameter("ecdsa-p256-sha256", "test-key-ecc-p256", "sig-b22",
                coveredHeaders);

        SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, params);

        signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, privateKey);

        signedResponse.setMessageBody("{\"bye\": \"world\"}");
        byte[] publicKey = KeyProvider.getPublicEccKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-ecc-p256", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);

        assertFalse(verify);
    }

}
