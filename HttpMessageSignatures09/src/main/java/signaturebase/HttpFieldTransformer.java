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
package signaturebase;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpMessage;

import signature.components.Component;

/**
 * Transformer class for preparation of the header fields for inclusion in the signature base
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 15.03.2022
 */
public class HttpFieldTransformer {

    private HttpFieldTransformer() {
        throw new IllegalStateException("HttpFieldTransformer class");
    }

    /**
     * Preparation of the header field values.
     * Allow safe transformations.
     * @param headerList
     *@return List of canonicalized headers.
     */
    protected static List<Component> canonicalizeHTTPFields(List<Component> coveredHeaders) {

        Iterator<Component> covereHeadersIterator = coveredHeaders.iterator();

        while (covereHeadersIterator.hasNext()) {
            Component item = covereHeadersIterator.next();
            //Section 2.1 Step 2 & 3
            //only for header fields
            if (!(item.getComponentId().startsWith("@"))) {
                String value = item.getValue();
                if (value == null) {
                    value = " ";
                }
                //removal of leading or trailing whitespace
                while (value.startsWith(" ") && (value.length() > 1)) {
                    value = value.replaceFirst(" ", "");
                }
                while (value.endsWith(" ")) {
                    value = value.substring(0, value.length() - 1);
                }
                //removal of obs-folds
                value = value.replaceAll("\t", "");
                item.setValue(value);

            }

        }
        return coveredHeaders;
    }

    /**
     * Header names are converted to lowercase.
     * Multiple headers are combined into one (section 2.1).
     * @return Message with prepared header field names
     */

    public static HttpMessage canonicalizeHTTPHeader(HttpMessage message) {
        HashMap<String, String> headermap = new HashMap<>();
        HeaderIterator headerIteratorCase = message.headerIterator();

        while (headerIteratorCase.hasNext()) {
            Header item = headerIteratorCase.nextHeader();
            String headerName = item.getName().toLowerCase();

            if (headermap.containsKey(headerName)) {
                String value = headermap.get(headerName);
                value = value + ", " + item.getValue();
                headermap.remove(headerName);
                headermap.put(headerName, value);

            } else {
                headermap.put(headerName, item.getValue());
            }

        }

        for (Map.Entry<String, String> entry : headermap.entrySet()) {
            message.removeHeaders(entry.getKey());
            message.addHeader(entry.getKey(), entry.getValue());
        }

        return message;

    }

}
