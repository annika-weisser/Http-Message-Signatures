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

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import httpmessagesignatures.Component;
import httpmessagesignatures.HttpMessageSignerFacade;
import httpmessagesignatures.KeyMap;
import httpmessagesignatures.SignatureParameter;
import httpmessagesignatures.SignedHttpMessageFactory;
import httpmessagesignatures.SignedHttpRequest;

/**
 * Checks whether invalid signatures are recognized.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 10.08.2022
 * @since PAS-X V3.2.4
 */
public class TestInvalidSignatures {

    /*
     * Equivalent to test case "B.2.3. Full Coverage using rsa-pss-sha512", but with invalid signature.
     */
    @Test
    public void testInvalidFullCoverage() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        String createValue = Instant.now().getEpochSecond() + "";

        List<Component> coveredHeaders = Arrays.asList(

                new Component("date"), new Component("@method", null, false), new Component("@path"),
                new Component("@query"), new Component("@authority"), new Component("content-type"),
                new Component("content-digest"), new Component("content-length"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond(), "sig-b23", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b23=(\"date\" \"@method\" \"@path\" \"@query\" "
                        + "\"@authority\" \"content-type\" \"content-digest\" \"content-length\")" + ";created="
                        + createValue + ";keyid=\"test-key-rsa-pss\";alg=\"rsa-pss-sha512\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        //change content-type header
        signedRequest.removeHeaders("content-type");
        signedRequest.addHeader("content-type", "text/plain");

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertFalse(verify);
    }

    /*
     * Equivalent to test case "Test Signing only QueryParasm" in Testclass TestQueryParams, but with invalid Signature.
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
        //change path
        signedRequest.setURI("/path?param=value&foo=bar&baz=batman&qux=bar");

        List<KeyMap> listeKeys = new ArrayList<>();
        byte[] pubicKey = KeyProvider.getSharedSecret();
        KeyMap map = new KeyMap("test-shared-secret", pubicKey);
        listeKeys.add(map);
        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertFalse(verify);
    }

}
