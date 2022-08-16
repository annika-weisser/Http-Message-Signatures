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

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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

/**
 * Test cases check the signing of the query params (based on Draft 9).
 * https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-09
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 03.05.2022
 */
public class TestQueryParams {

    /*
     * Test Signing only QueryParasm
     */
    @Test
    public void testQueryParams() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getSharedSecret();
        URI uri = new URI("/path?param=value&foo=bar&baz=batman&qux=");
        request.setURI(uri);

        List<Component> coveredHeaders = Arrays.asList();
        Component[] array = coveredHeaders.toArray(new Component[0]);
        coveredHeaders = new ArrayList<>(Arrays.asList(array));
        coveredHeaders = coveredHeaders.stream().map(s -> s).collect(Collectors.toList());

        NameValuePair parametersBaz = new BasicNameValuePair("name", "baz");
        NameValuePair parametersQux = new BasicNameValuePair("name", "qux");
        NameValuePair parametersParam = new BasicNameValuePair("name", "param");

        coveredHeaders.add(new Component("@query-params", parametersBaz, false));
        coveredHeaders.add(new Component("@query-params", parametersQux, false));
        coveredHeaders.add(new Component("@query-params", parametersParam, false));

        SignatureParameter params = new SignatureParameter("hmac-sha256", "test-shared-secret",
                Instant.now().getEpochSecond(), "sig-b26", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        List<KeyMap> listeKeys = new ArrayList<>();
        byte[] pubicKey = KeyProvider.getSharedSecret();
        KeyMap map = new KeyMap("test-shared-secret", pubicKey);
        listeKeys.add(map);
        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Test Signing QueryParam and further components
     */
    @Test
    public void testQueryParamsWithComponents() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        URI uri = new URI("/path?param=value&foo=bar&baz=batman&qux=");
        request.setURI(uri);
        byte[] privateKey = KeyProvider.getSharedSecret();

        List<Component> coveredHeaders = Arrays.asList();
        Component[] array = coveredHeaders.toArray(new Component[0]);
        coveredHeaders = new ArrayList<>(Arrays.asList(array));
        coveredHeaders = coveredHeaders.stream().map(s -> s).collect(Collectors.toList());

        NameValuePair parametersBaz = new BasicNameValuePair("name", "baz");
        NameValuePair parametersQux = new BasicNameValuePair("name", "qux");
        NameValuePair parametersParam = new BasicNameValuePair("name", "param");

        coveredHeaders.add(new Component("date"));
        coveredHeaders.add(new Component("@query-params", parametersBaz, false));
        coveredHeaders.add(new Component("content-type"));
        coveredHeaders.add(new Component("@query-params", parametersQux, false));
        coveredHeaders.add(new Component("@query-params", parametersParam, false));
        coveredHeaders.add(new Component("content-length"));

        SignatureParameter params = new SignatureParameter("hmac-sha256", "test-key-ed25519",
                Instant.now().getEpochSecond(), "sig-b26", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        List<KeyMap> listeKeys = new ArrayList<>();
        byte[] pubicKey = KeyProvider.getSharedSecret();
        KeyMap map = new KeyMap("test-key-ed25519", pubicKey);
        listeKeys.add(map);
        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }
}
