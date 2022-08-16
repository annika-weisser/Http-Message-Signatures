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
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpVersion;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import httpmessagesignatures.Component;
import httpmessagesignatures.HttpMessageSignerFacade;
import httpmessagesignatures.KeyMap;
import httpmessagesignatures.SignatureParameter;
import httpmessagesignatures.SignedHttpMessageFactory;
import httpmessagesignatures.SignedHttpRequest;

/**
 * Test cases check whether the signature remains valid when performing secure transformation of the signed message.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 26.04.2022
 */
public class TestSafeTransformation {

    public static HttpPost getTestRequest() throws URISyntaxException, UnsupportedEncodingException {

        URI uri = new URI("http://example.com/foo?param=Value&Pet=dog");
        HttpPost postRequest = new HttpPost(uri);
        postRequest.addHeader("Host", uri.getHost());
        postRequest.addHeader("Date", "Tue, 20 Apr 2021 02:07:55 GMT");
        postRequest.addHeader("Content-Type", "application/json");
        postRequest.addHeader("Content-Digest",
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:");
        postRequest.addHeader("Content-Length", "18");
        String body = "{\"hello\": \"world\"}";
        StringEntity entity = new StringEntity(body);
        postRequest.setEntity(entity);
        return postRequest;

    }

    /*
     * The reordering of header fields with different header field names.
     */
    @Test
    public void testRearrangementHeader() throws Exception {
        HttpPost request = getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"),
                new Component("content-type", null, false), new Component("host"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                request.getEntity().getContent().toString());

        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);
        signedRequest.removeHeaders("Host");
        signedRequest.removeHeaders("Content-Type");
        signedRequest.addHeader("Content-Type", "application/json");
        signedRequest.addHeader("Host", "example.com");

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    @Test
    public void testCombinationHeader() throws Exception {
        HttpPost request = getTestRequest();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("host", null, false),
                new Component("date"), new Component("example", null, false));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        request.addHeader("Date", "Tue, 21 Apr 2021 02:07:55 GMT");
        request.addHeader("Example", "en=\"Applepie\"");
        request.addHeader("Example", "da=:w4ZibGV0w6ZydGU=:");

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);

        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);
        signedRequest.removeHeaders("Date");
        signedRequest.addHeader("Date", "Tue, 20 Apr 2021 02:07:55 GMT" + ", " + "Tue, 21 Apr 2021 02:07:55 GMT");
        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Conversion between different versions of the HTTP protocol.
     */
    @Test
    public void testConvertProtocolVersion() throws Exception {
        HttpPost request = getTestRequest();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("host"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);

        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);
        assertEquals(signedRequest.getProtocolVersion(), HttpVersion.HTTP_1_1);

        signedRequest.setProtocolVersion(HttpVersion.HTTP_1_0);

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Changes in casing (e.g., "Origin" to "origin") of any case-insensitive components
     */
    @Test
    public void testCapitalizationChanges() throws Exception {
        HttpPost request = getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@scheme"), new Component("content-digest"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));

        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);
        // String uri = new URI("HTTP://example.com/foo?param=Value&Pet=dog");
        signedRequest.setURI("HTTP://example.com/foo?param=Value&Pet=dog");

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Addition or removal of leading or trailing whitespace to a header field value.
     */
    @Test
    public void testAddWhitespaceHeader() throws Exception {
        HttpPost request = getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"),
                new Component("content-type", null, false), new Component("host"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        signedRequest.removeHeaders("Content-Type");
        signedRequest.addHeader("Content-Type", "    application/json    ");

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);

    }

    /*
     * Addition or removal of obs-folds.
     */
    @Test
    public void testObsFolds() throws Exception {
        HttpPost request = getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"),
                new Component("content-type", null, false), new Component("host"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        signedRequest.removeHeaders("Content-Type");
        signedRequest.addHeader("Content-Type", " application/json" + "\t");

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Safe Transformation of request target.
     */
    @Test
    public void testChangesRequesTarget() throws Exception {
        HttpPost request = getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("content-type"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b22", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);

        //        signedRequest.setURI(new URI("http://www.example.org:8080/pub/WWW/TheProject.html"));
        signedRequest.setURI("http://www.example.org:8080/pub/WWW/TheProject.html");

        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        signedRequest.removeHeaders("Content-Type");
        signedRequest.addHeader("Content-Type", " application/json" + "\t");

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }
}
