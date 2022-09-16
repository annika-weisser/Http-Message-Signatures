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

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

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
    private URI uri;
    /** BasicRequestline of the request */
    private BasicRequestLine requestline;

    /**
     * Constructor.
     * @param method
     * @param uri
     * @param signatureParams
     * @throws URISyntaxException
     */
    public SignedHttpRequest(final String method, final String uri, SignatureParameter signatureParams)
            throws URISyntaxException {
        super(signatureParams);
        this.method = method;
        this.uri = new URI(uri);
        requestline = null;
    }

    /**
     * Constructor.
     * @param method
     * @param uri
     * @param signatureParams
     * @param messageBody
     * @throws URISyntaxException
     */
    public SignedHttpRequest(final String method, final String uri, SignatureParameter signatureParams,
            String messageBody) throws URISyntaxException {
        super(signatureParams);
        this.method = method;
        this.uri = new URI(uri);
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
        requestline = new BasicRequestLine(method, uri.toString(), version);
    }

    /**
     * @param uri
     * @throws URISyntaxException
     */
    public void setURI(String uri) throws URISyntaxException {

        if (requestline != null) {
            requestline = new BasicRequestLine(method, uri, requestline.getProtocolVersion());
        }
        this.uri = new URI(uri);

    }

    /**
     * @param uri
     */
    public URI getURI() {
        return uri;
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

    /** (non-Javadoc)
     * set dns-target parameter
     */
    public void setDnsTarget() {
        try {

            String host = uri.getHost();
            super.signatureParams.setDnsTarget(InetAddress.getByName(host).getHostAddress());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

    }

}
