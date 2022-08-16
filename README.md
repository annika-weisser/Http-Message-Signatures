# Http-Message-Signatures

On behalf of the Körber Pharma Software GmbH I designed an implementation of the [HTTP Message Signatures mechanism](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures) in Java. This implementation is mainly based on the draft of [version 09](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-09).

The following basic components are included:
  -	Creation of a signature base for the covered components of the HTTP message on which the signature is applied.
  -	Components can be header fields or components derived from the message:
      - Header fields: canonization of structured HTTP fields: dictionary fields inclusion of the sf parameter
  -	The following signature algorithms can be selected:
    - rsa-pss-sha512
    - hmac-sha256
    - ecdsa-p256-sha256
    - ed25519
  -	Multiple signatures can be attached to a message.
  -	The test cases B.2.1 – B.2.5 from the draft are included as JUnit tests (see test class "HttpMessageSignatureTest")
  -	Also: Request signature binding based on draft version 10 (specification of the req parameter).
  
Another function is built in that is not included in the specification: A message body integrity check is carried out as soon as the content digest header is contained in a signature to be checked. It is checked whether the hash value in the content digest header matches the message body.
The function of the Accept-Signature Field is not included in the implementation so far.

# Usage
The components covered are specified via a list of components:
```
        List<Component> coveredHeadersResponse = Arrays.asList(new Component("@authority", true),   new Component("content-digest"), new Component("signature", parameterSiganture, true));
```
A component contains a component ID e.g. "@authorithy". Furthermore, a parameter can be specified for the component (e.g. "sf") and the req flag can be set to true if there is a request-response binding.
Then the signature parameters are set. In this implementation, the covered components belong to the signature components:
```
SignatureParameter responseParams = new SignatureParameter("hmac-sha256", "test-shared-secret", Instant.now().getEpochSecond(), "sig-b24", coveredHeadersResponse);
```

Then a message to be signed is created:
```
SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response, responseParams, signedRequest);
```
For the signing process, the message to be signed is handed over together with the key:
```
signedResponse = HttpMessageSignerFacade.signResponse(signedResponse, privateKey);
```

Verification process:
Create a SignedHttpRequest/Response from the HttpRequest/HttpResponse:
```
SignedHttpResponse signedResponse = SignedHttpMessageFactory.createSignedHttpResponse(response);
```

Since multiple signatures can be verified the corresponding public keys and key IDs are add into a list of KeyMap.
```
  List<KeyMap> listeKeys = new ArrayList<>();
        KeyMap map = new KeyMap("test-shared-secret", sharedKey);
        listeKeys.add(map);
```
        
For verification, pass the message and list of KeyMaps:
```
boolean verifyResponse = HttpMessageSignerFacade.verifyResponse(signedResponse, listeKeys);
```
The Boolean return value indicates whether the signature is valid.

# Maven
```
<dependency>
<groupId>HttpMessageSignatures</groupId>
<artifactId>HttpMessageSignatures09</artifactId>
	<version>0.0.1-SNAPSHOT</version>
</dependency>
```


