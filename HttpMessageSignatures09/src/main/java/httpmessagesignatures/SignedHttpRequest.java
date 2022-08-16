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

import org.apache.http.HttpRequest;
import org.apache.http.HttpVersion;
import org.apache.http.ProtocolVersion;
import org.apache.http.message.BasicRequestLine;

/**
 * SignedHttpRequest contains attributes of a signed request.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 20.05.2022
 */
public class SignedHttpRequest extends SignedHttpMessage implements HttpRequest {
    /** HTTP method of request */
    private final String method;
    /** URI of the request */
    private String uri;
    /** BasicRequestline of the request */
    private BasicRequestLine requestline;

    /**
     * Constructor.
     * @param method
     * @param uri
     * @param signatureParams
     */
    public SignedHttpRequest(final String method, final String uri, SignatureParameter signatureParams) {
        super(signatureParams);
        this.method = method;
        this.uri = uri;
        requestline = null;
    }

    /**
     * Constructor.
     * @param method
     * @param uri
     * @param signatureParams
     * @param messageBody
     */
    public SignedHttpRequest(final String method, final String uri, SignatureParameter signatureParams,
            String messageBody) {
        super(signatureParams);
        this.method = method;
        this.uri = uri;
        this.messageBody = messageBody;
        requestline = null;

    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpMessage#getProtocolVersion()
     */
    @Override
    public ProtocolVersion getProtocolVersion() {
        return getRequestLine().getProtocolVersion();
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpRequest#getRequestLine()
     */
    @Override
    public BasicRequestLine getRequestLine() {
        if (requestline == null) {
            requestline = new BasicRequestLine(method, uri.toString(), HttpVersion.HTTP_1_1);
        }
        return requestline;
    }

    /**
     * @return the method
     */
    public String getMethod() {
        return method;
    }

    /**
     * @param version
     */
    public void setProtocolVersion(HttpVersion version) {
        requestline = new BasicRequestLine(method, uri, version);
    }

    /**
     * @param uri
     */
    public void setURI(String uri) {
        this.uri = uri;
        if (requestline != null) {
            requestline = new BasicRequestLine(method, uri, requestline.getProtocolVersion());
        }

    }

    /**
    * @param messageBody
     */
    @Override
    void setMessageBody(String messageBody) {
        this.messageBody = messageBody;

    }

    /**
     * return the messageBody
     */
    @Override
    String getMessageBody() {

        return messageBody;
    }

}
