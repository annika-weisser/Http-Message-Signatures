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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.http.HeaderElement;
import org.apache.http.HttpRequest;
import org.apache.http.NameValuePair;

/**
 * Performs specific steps for creating a SignatureBase for a response.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 24.05.2022
 */
public class SignaturBaseCreatorResponse extends SignaturBaseCreator {
    /** response to be signed/verified */
    private SignedHttpResponse response;

    /**
     * Constructor.
     * @param coveredHeaders List of covered headers.
     * @param response Response to be signed/verified.
     * @param params The signature parameters.
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     */
    public SignaturBaseCreatorResponse(List<Component> coveredHeaders, SignedHttpResponse response,
            SignatureParameter params) throws NoSuchAlgorithmException, URISyntaxException {
        super(response);
        this.coveredHeaders = coveredHeaders;
        this.params = params;
        this.response = response;

        create();
    }

    /**
     * initialize the SignatureBase creation
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     */
    @Override
    protected void create() throws NoSuchAlgorithmException, URISyntaxException {

        addHeaders();
        addDerivedComponent();

        if (response.getRelatedHttpRequest() != null) {
            relatedDerivedComponents(response);
            relatedComponents(response);
        }

        //2.1 merge duplicate headers
        coveredHeaders = HttpFieldTransformer.canonicalizeHTTPFields(coveredHeaders);
        signaturebase = createSignatureBaseForMessage(response, params);
    }

    /**
     * Check whether derived components are included in the covered components and derive the values for them.
     */
    private void addDerivedComponent() {
        Iterator<Component> coveredHeadersIterator = coveredHeaders.iterator();
        while (coveredHeadersIterator.hasNext()) {
            Component item = coveredHeadersIterator.next();
            if (item.getComponentId().contains("@status")) {
                item.setValue("" + response.getStatusLine().getStatusCode());
            }
        }

    }

    /**
     * add the related header components of a connected request (Request-Response Signature Binding)
     * @param response
     * @param headerList
     */
    private void relatedComponents(SignedHttpResponse response) {
        HttpRequest request = response.getRelatedHttpRequest();
        //request has to be canonicalize
        request = (HttpRequest) HttpFieldTransformer.canonicalizeHTTPHeader(request);
        // iterate throw coveredHeaders
        Iterator<Component> coveredHeadersIterator = coveredHeaders.iterator();
        while (coveredHeadersIterator.hasNext()) {
            Component component = coveredHeadersIterator.next();
            String componentId = component.getComponentId();
            //search for req;, no derived components
            if ((component.isReq()) && (!(component.getComponentId().startsWith("@")))) {
                String value;

                if (component.getComponentId().contains("signature")) {
                    // get signature label from component
                    String sigLabel = "";
                    NameValuePair[] parameters = component.getParameter();
                    for (NameValuePair parameter : parameters) {
                        if (parameter.getName().equals("key")) {
                            sigLabel = parameter.getValue();
                        }
                    }

                    HeaderElement[] ele = request.getFirstHeader("Signature").getElements();
                    for (HeaderElement element : ele) {
                        if (element.getName().equals(sigLabel)) {
                            value = element.getValue();
                            component.setValue(value);

                        }
                    }
                } else {
                    value = request.getFirstHeader(componentId).getValue();
                    component.setValue(value);
                }

            }

        }

    }

    /**
     * add the derived components of a connected request (Request-Response Signature Binding)
     * @param response
     * @param headerList List of all message headers.
     * @throws URISyntaxException
     * @throws Exception
     *
     */
    private void relatedDerivedComponents(SignedHttpResponse response) throws URISyntaxException {

        HashMap<String, String> allQueryParams;
        HttpRequest request = response.getRelatedHttpRequest();

        URI uri = new URI(request.getRequestLine().getUri());
        allQueryParams = getQueryParams(request);

        for (Component component : coveredHeaders) {
            String componentId = component.getComponentId();
            //only fetch the values from the request for the components that are also marked as related
            if (component.isReq()) {
                if (componentId.contains("@method")) {

                    component.setValue(request.getRequestLine().getMethod());

                }

                if (componentId.contains("@target-uri")) {

                    component.setValue(request.getRequestLine().getUri().toLowerCase());

                }

                if (componentId.contains("@request-target")) {

                    component.setValue(uri.getPath().toLowerCase() + uri.getQuery().toLowerCase());

                }

                if (componentId.contains("@authority")) {

                    component.setValue(uri.getAuthority().toLowerCase());

                }

                if (componentId.contains("@scheme") && (uri.getScheme() != null)) {

                    component.setValue(uri.getScheme().toLowerCase()); //must be case-insensitive

                }

                if (componentId.contains("@path")) {

                    component.setValue(uri.getPath().toLowerCase());

                }

                if (componentId.contains("@query")) {

                    component.setValue("?" + uri.getQuery());

                }

                if (componentId.contains("@query-params")) {

                    NameValuePair[] parameters = component.getParameter();
                    String value = "";
                    for (NameValuePair parameter : parameters) {
                        if (parameter.getName().equals("name")) {
                            HashMap<String, String> queryparams = allQueryParams;
                            if (uri.getQuery().contains(parameter.getValue())) {
                                value = queryparams.get(parameter.getValue());
                            }

                        }
                    }
                    component.setValue(value);
                }
            }

        }

    }

}
