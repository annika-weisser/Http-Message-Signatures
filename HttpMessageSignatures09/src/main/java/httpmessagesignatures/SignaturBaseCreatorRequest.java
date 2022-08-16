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
import java.util.List;

import org.apache.http.NameValuePair;

/**
 * Performs specific steps for creating a SignatureBase for a request.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 24.05.2022
 */
public class SignaturBaseCreatorRequest extends SignaturBaseCreator {
    /** request to be signed/verified */
    private SignedHttpRequest request;

    /**
     * Constructor.
     * @param coveredHeaders List of covered headers.
     * @param request Request to be signed/verified.
     * @param params The signature parameters.
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     */
    public SignaturBaseCreatorRequest(List<Component> coveredHeaders, SignedHttpRequest request,
            SignatureParameter params) throws NoSuchAlgorithmException, URISyntaxException {
        super(request);
        this.coveredHeaders = coveredHeaders;
        this.params = params;
        this.request = request;
        create();
    }

    /**
     * initialize the SignatureBase creation
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     */
    @Override
    protected void create() throws URISyntaxException, NoSuchAlgorithmException {

        addHeaders();
        addDerivedComponents();
        //2.1 merge duplicate headers
        coveredHeaders = HttpFieldTransformer.canonicalizeHTTPFields(coveredHeaders);
        signaturebase = createSignatureBaseForMessage(request, params);
    }

    /**
     * @param headerList List of all message headers.
     * @return headerList to which the derived components are added
     * @throws URISyntaxException
     */
    private void addDerivedComponents() throws URISyntaxException {
        HashMap<String, String> allQueryParams;
        URI uri = new URI(request.getRequestLine().getUri());
        allQueryParams = getQueryParams(request);

        for (Component component : coveredHeaders) {
            String componentId = component.getComponentId();
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

            if (componentId.contains("@scheme")) {

                if (uri.getScheme().toLowerCase() != null) {
                    component.setValue(uri.getScheme().toLowerCase()); //must be case-insensitive
                }

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
