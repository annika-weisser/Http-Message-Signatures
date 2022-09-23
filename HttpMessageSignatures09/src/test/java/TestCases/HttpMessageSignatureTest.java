package TestCases;

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import httpmessagesignatures.Component;
import httpmessagesignatures.HttpMessageSignerFacade;
import httpmessagesignatures.KeyMap;
import httpmessagesignatures.SignatureParameter;
import httpmessagesignatures.SignedHttpMessageFactory;
import httpmessagesignatures.SignedHttpRequest;
import httpmessagesignatures.SignedHttpResponse;

/**
 * Contains the test cases from the HTTP Message Signatures Draft Version 9 (see Section B.2. Test Cases).
 * https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-09
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 20.04.2022
 */
public class HttpMessageSignatureTest {

    /*
     * Test Case B.2.1 Minimal Signature Using rsa-pss-sha512
     */
    @Test
    public void testMinimalSignature() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        String createValue = Instant.now().getEpochSecond() + "";

        List<Component> coveredHeaders = Arrays.asList();
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                "b3k2pp5k7z-50gnwp.yemd", "sig-b21", coveredHeaders);
        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b21=();created=" + createValue
                        + ";keyid=\"test-key-rsa-pss\";alg=\"rsa-pss-sha512\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Test Case B.2.2.  Selective Covered Components using rsa-pss-sha512
     */
    @Test
    public void testSelectiveCoveresComponents() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        String createValue = Instant.now().getEpochSecond() + "";

        List<Component> coveredHeaders = Arrays.asList(new Component("@authority"), new Component("content-digest"));
        Long created = Instant.now().getEpochSecond();
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss", "sig-b22",
                coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b22=(\"@authority\" \"content-digest\");created=" + createValue
                        + ";keyid=\"test-key-rsa-pss\";alg=\"rsa-pss-sha512\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);

        assertTrue(verify);
    }

    /*
     * B.2.3. Full Coverage using rsa-pss-sha512
     */
    @Test
    public void testFullCoverage() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();
        String createValue = Instant.now().getEpochSecond() + "";

        List<Component> coveredHeaders = Arrays.asList(

                new Component("date"), new Component("@method", null, false), new Component("@path"),
                new Component("@query"), new Component("@authority"), new Component("content-type"),
                new Component("content-digest"), new Component("content-length"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss", "sig-b23",
                coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b23=(\"date\" \"@method\" \"@path\" \"@query\" "
                        + "\"@authority\" \"content-type\" \"content-digest\" \"content-length\")" + ";created="
                        + createValue + ";keyid=\"test-key-rsa-pss\";alg=\"rsa-pss-sha512\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * B.2.4. Signing a Response using ecdsa-p256-sha256
     */
    @Test
    public void testSigningResponseUsingEcdsaP256Sha256() throws Exception {
        HttpResponse response = TestMessagProvider.getResponse();
        String createValue = Instant.now().getEpochSecond() + "";
        byte[] privateKey = KeyProvider.getPrivateEccKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@status"), new Component("content-type"),
                new Component("content-digest"), new Component("content-length"));
        SignatureParameter params = new SignatureParameter("ecdsa-p256-sha256", "test-key-ecc-p256", "sig-b24",
                coveredHeaders);

        SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, params);

        signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, privateKey);

        assertEquals(
                "sig-b24=(\"@status\" \"content-type\" " + "\"content-digest\" \"content-length\");created="
                        + createValue + ";keyid=\"test-key-ecc-p256\";alg=\"ecdsa-p256-sha256\"",
                signedResponse.getFirstHeader("Signature-Input").getValue());

        byte[] publicKey = KeyProvider.getPublicEccKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-ecc-p256", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);
        assertTrue(verify);
    }

    /*
     * B.2.5. Signing a Request using hmac-sha256
     */
    @Test
    public void testSigningRequestUsingHmacSha256() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        String createValue = Instant.now().getEpochSecond() + "";
        byte[] secret = KeyProvider.getSharedSecret();

        List<Component> coveredHeaders = Arrays.asList(new Component("date", null, false),
                new Component("@authority", null, false), new Component("content-type", null, false));
        SignatureParameter params = new SignatureParameter("hmac-sha256", "test-shared-secret", "sig-b25",
                coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, secret);

        assertEquals(
                "sig-b25=(\"date\" \"@authority\" \"content-type\");created=" + createValue
                        + ";keyid=\"test-shared-secret\";alg=\"hmac-sha256\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-shared-secret", secret);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * B.2.6. Signing a Request using ed25519
     */
    @Test
    public void testSigningRequestUsingEd25519() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        String createValue = Instant.now().getEpochSecond() + "";
        byte[] privateKey = KeyProvider.getEd25519PrivateKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("date", null, false),
                new Component("@method", null, false), new Component("@path", null, false),
                new Component("@authority", null, false), new Component("content-type", null, false),
                new Component("content-length", null, false));
        SignatureParameter params = new SignatureParameter("ed25519", "test-key-ed25519", "sig-b26", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" "
                        + "\"content-type\" \"content-length\");created=" + createValue
                        + ";keyid=\"test-key-ed25519\";alg=\"ed25519\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        List<KeyMap> listeKeys = new ArrayList<>();
        byte[] pubicKey = KeyProvider.getEd25519PublicKey();
        KeyMap map = new KeyMap("test-key-ed25519", pubicKey);
        listeKeys.add(map);
        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Additional test request with expire parameter.
     */
    @Test
    public void testExpiredSignatureRequest() throws Exception {

        HttpPost request = TestMessagProvider.getTestRequest();
        byte[] privateKey = KeyProvider.getRsaPssPrivateKey();

        List<Component> coveredHeaders = Arrays.asList(

                new Component("date"), new Component("@method", null, false), new Component("@path"),
                new Component("@query"), new Component("@authority"), new Component("content-type"),
                new Component("content-digest"), new Component("content-length"));
        SignatureParameter params = new SignatureParameter("rsa-pss-sha512", "test-key-rsa-pss",
                Instant.now().getEpochSecond() + 200, "sig-b23", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params,
                EntityUtils.toString(request.getEntity()));
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        byte[] publicKey = KeyProvider.getRsaPssPublicKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-rsa-pss", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

    /*
     * Additional test response with expire parameter.
     */
    @Test
    public void testExpiredSignatureResponse() throws Exception {
        HttpResponse response = TestMessagProvider.getResponse();
        long createValue = Instant.now().getEpochSecond();
        byte[] privateKey = KeyProvider.getPrivateEccKey();

        List<Component> coveredHeaders = Arrays.asList(new Component("@status"), new Component("content-type"),
                new Component("content-digest"), new Component("content-length"));
        SignatureParameter params = new SignatureParameter("ecdsa-p256-sha256", "test-key-ecc-p256", createValue + 200,
                "sig-b24", coveredHeaders);

        SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, params);

        signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, privateKey);

        byte[] publicKey = KeyProvider.getPublicEccKey();
        List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-key-ecc-p256", publicKey);
        listeKeys.add(map);

        boolean verify = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);
        assertTrue(verify);
    }

    /*
     * Additional test request with dns-target parameter.
     */
    @Test
    public void testDnsTargetParameter() throws Exception {
        HttpPost request = TestMessagProvider.getTestRequest();
        String createValue = Instant.now().getEpochSecond() + "";
        byte[] privateKey = KeyProvider.getEd25519PrivateKey();

        request.setURI(new URI("//localhost/foo?param=Value&Pet=dog"));

        List<Component> coveredHeaders = Arrays.asList(new Component("date", null, false),
                new Component("@method", null, false), new Component("@path", null, false),
                new Component("@authority", null, false), new Component("content-type", null, false),
                new Component("content-length", null, false));
        SignatureParameter params = new SignatureParameter("ed25519", "test-key-ed25519", "sig-b26", coveredHeaders);

        SignedHttpRequest signedRequest = SignedHttpMessageFactory.createSignedHttpRequest(request, params);
        signedRequest.setDnsTarget();
        signedRequest = HttpMessageSignerFacade.signRequest(signedRequest, privateKey);

        assertEquals(
                "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" "
                        + "\"content-type\" \"content-length\");created=" + createValue
                        + ";keyid=\"test-key-ed25519\";alg=\"ed25519\";dns-target=\"127.0.0.1\"",
                signedRequest.getFirstHeader("Signature-Input").getValue());

        List<KeyMap> listeKeys = new ArrayList<>();
        byte[] pubicKey = KeyProvider.getEd25519PublicKey();
        KeyMap map = new KeyMap("test-key-ed25519", pubicKey);
        listeKeys.add(map);
        boolean verify = HttpMessageSignerFacade.verifyRequest(signedRequest, listeKeys);
        assertTrue(verify);
    }

}
