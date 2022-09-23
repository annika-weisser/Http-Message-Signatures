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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
 * Clas contains test cases for structure header fields.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 07.08.2022
 * @since PAS-X V3.2.4
 */
public class TestStructureFields {

    @Test
    public void testDictionary() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        String createValue = Instant.now().getEpochSecond() + "";

        NameValuePair parameterB = new BasicNameValuePair("key", "b");
        NameValuePair parametersSf = new BasicNameValuePair("sf", null);

        request.addHeader("Example-Dict", "a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid");

        List<Component> coveredHeaders = Arrays.asList(new Component("example-dict", parameterB, false),
                new Component("example-dict"), new Component("example-dict", parametersSf, false),
                new Component("date"), new Component("@method", null, false), new Component("@path"),
                new Component("@query"), new Component("@authority"), new Component("content-type"),
                new Component("content-digest"), new Component("content-length"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss", "sig-b23",
                coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b23=(\"example-dict\";key=\"b\" \"example-dict\" \"example-dict\";sf \"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" \"content-length\");created="
                        + createValue + ";keyid=\"test-key-rsa-pss\";alg=\"rsa-pss-sha512\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

}
