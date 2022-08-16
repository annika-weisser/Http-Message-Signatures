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

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpRequest;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;

/**
 * SignatureBaseCreator for creating the signature base for signing/verifying an HTTP message.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 13.03.2022
 */
public abstract class SignaturBaseCreator {

    /** list of header identifiers of the headers covered by the signature */
    protected List<Component> coveredHeaders = null;
    /** parameters associated with the signature */
    protected SignatureParameter params;
    /** signaturebase as byte array */
    protected byte[] signaturebase;
    /** signature-input */
    protected String signatureInput;
    /** message to be signed/verified */
    protected SignedHttpMessage message;

    SignaturBaseCreator(SignedHttpMessage message) {
        this.message = message;
    }

    protected abstract void create() throws Exception;

    /**
     * Extract the query parameters from the URI.
     * @param Request
     * @return HashMap containing the query-params
     * @throws URISyntaxException
     * @throws Exception
     */
    protected HashMap<String, String> getQueryParams(HttpRequest request) throws URISyntaxException {
        HashMap<String, String> query = new HashMap<>();

        String uri = request.getRequestLine().getUri();
        List<NameValuePair> queryParams = new URIBuilder(uri).getQueryParams();
        Iterator<NameValuePair> queryIterator = queryParams.iterator();

        while (queryIterator.hasNext()) {
            NameValuePair pair = queryIterator.next();
            query.put(pair.getName(), pair.getValue());
        }

        return query;
    }

    /**
     * @return Signaturbase as byte array
     */
    protected byte[] getSignaturebase() {
        return signaturebase;
    }

    /**
     * Determines the components of the signaturebase and puts them together.
     * @param message
     * @param sigparams
     * @param headerlist
     * @return Returns the bytes of the signature base
     * @throws NoSuchAlgorithmException
     */
    public byte[] createSignatureBaseForMessage(SignedHttpMessage message, SignatureParameter sigparams)
            throws NoSuchAlgorithmException {
        this.message = message;

        //check if the message body is covered by the signature
        checkCoveredMessageBody();

        String signaturbase = "";

        //
        Iterator<Component> componentIterator = coveredHeaders.iterator();

        while (componentIterator.hasNext()) {
            Component item = componentIterator.next();
            String componentId = item.getComponentId().toLowerCase();

            signaturbase = signaturbase + "\"" + componentId + "\"";
            //check if component contains parameters
            NameValuePair[] parameters = item.getParameter();
            if (parameters != null) {
                for (NameValuePair parameter : parameters) {
                    if (parameter != null) {
                        signaturbase = signaturbase + ";" + parameter.getName();
                        if (parameter.getValue() != null) {
                            signaturbase = signaturbase + "=" + "\"" + parameter.getValue() + "\"";
                        }
                    }

                }
            }

            signaturbase = signaturbase + ":" + " " + item.getValue();

            signaturbase = signaturbase + '\n';

        }

        signaturbase = signaturbase + "\"" + "@signature-params" + "\"" + ": " +

                createBaseLine() + sigparams.createCanonicalizedValue();

        signatureInput = createBaseLine() + sigparams.createCanonicalizedValue();
        return signaturbase.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * @throws NoSuchAlgorithmException
     *
     */
    private void checkCoveredMessageBody() throws NoSuchAlgorithmException {
        Iterator<Component> coveredHeadersIterator = coveredHeaders.iterator();
        while (coveredHeadersIterator.hasNext()) {
            Component component = coveredHeadersIterator.next();
            String componentId = component.getComponentId();

            if (componentId.equals("content-digest")) {

                //check if request contains a message-body
                if (message.getMessageBody() != null) {
                    String body = message.getMessageBody();
                    //create content-digest Header
                    if (!message.containsHeader("content-digest")) {
                        String bodyHash = createContentDigestHeader(body);
                        component.setValue(bodyHash);
                        message.addHeader("content-digest", bodyHash);
                    } else {
                        component.setValue(message.getFirstHeader("content-digest").getValue());
                    }

                }

            }
        }

    }

    /**
     * @return String of BaseLine
     */
    protected String createBaseLine() {
        String value = "(";
        Iterator<Component> covereHeadersIterator = coveredHeaders.iterator();
        while (covereHeadersIterator.hasNext()) {
            Component item = covereHeadersIterator.next();
            //add signature-base-line: componenId and parameters
            NameValuePair[] parameters = item.getParameter();
            if (parameters != null) {
                value = value + "\"" + item.getComponentId().toLowerCase() + "\"";
                //add all Parameters
                for (NameValuePair parameter : parameters) {
                    if (parameter != null) {
                        if (parameter.getValue() != null) {
                            value = value + ";" + parameter.getName().toLowerCase() + "=" + "\"" + parameter.getValue()
                                    + "\"";
                        } else {
                            value = value + ";" + parameter.getName().toLowerCase();
                        }
                    }

                }

            } else {
                //component has no parameters
                value = value + "\"" + item.getComponentId().toLowerCase() + "\"";
            }
            //separate components with spaces
            if (covereHeadersIterator.hasNext()) {
                value = value + " ";
            }

        }
        value = value + ")";
        return value;
    }

    /**
     * @param String of message body
     * @throws NoSuchAlgorithmException
     */
    public String createContentDigestHeader(String body) throws NoSuchAlgorithmException {
        //256-Sha function is used by default
        String headerValue = "sha-256=:" + SHAEncoder.hash256(body);

        return headerValue;
    }

    /**
     * add Headervalues to component
     */
    protected void addHeaders() {

        for (Component component : coveredHeaders) {
            String componentId = component.getComponentId();
            //only for header fields
            if (!componentId.contains("@") && (!component.isReq())) {
                Header componentHeader = message.getFirstHeader(componentId);
                String value = "";
                NameValuePair[] parameters = component.getParameter();
                if ((parameters == null) || (parameters.length == 0)) {
                    value = componentHeader.getValue();
                } else {

                    for (NameValuePair parameter : parameters) {
                        if (parameter == null) {
                            value = componentHeader.getValue();
                        } else {
                            if (parameter.getName().equals("sf")) {
                                value = componentHeader.getValue();
                            } else {
                                HeaderElement[] elements = componentHeader.getElements();
                                for (HeaderElement element : elements) {
                                    if (element.getName().equals(parameter.getValue())) {
                                        value = element.getValue();
                                    }
                                }
                            }
                        }

                    }
                }
                component.setValue(value);

            }
        }

    }

}
