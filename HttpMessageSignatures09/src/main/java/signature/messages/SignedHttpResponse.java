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
package signature.messages;

import java.util.List;
import java.util.Locale;

import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.ProtocolVersion;
import org.apache.http.ReasonPhraseCatalog;
import org.apache.http.StatusLine;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.util.Args;

import signature.components.SignatureParameter;

/**
 * SignedHttpResponse contains attributes of a signed response.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 20.05.2022
 */
public class SignedHttpResponse extends SignedHttpMessage implements HttpResponse {

    /** statusline of response message */
    private StatusLine statusline;
    /** protocol version of response message */
    private ProtocolVersion version;
    /** status code of response message */
    private int code;
    /** reason phrase of response message */
    private String reasonPhrase;
    /** http entity contains the response message*/
    private HttpEntity entity;
    /** ReasonPhraseCatalog of the response message */
    private final ReasonPhraseCatalog reasonCatalog;
    /** locale of response message */
    private Locale locale;
    /** related request (Request-Response Signature Binding) */
    private HttpRequest relatedRequest;
    /** list of related signature label for   @signature;req component (Request-Response Signature Binding)*/
    private List<String> relatedSingatureLabel;

    /**
     * Constructor.
     * @param signatureParams
     * @param statusline
     * @param catalog
     * @param locale
     * @param responseBody
     */
    public SignedHttpResponse(SignatureParameter signatureParams, final StatusLine statusline,
            final ReasonPhraseCatalog catalog, final Locale locale, String responseBody) {
        super(signatureParams);

        this.statusline = Args.notNull(statusline, "Status line");
        version = statusline.getProtocolVersion();
        code = statusline.getStatusCode();
        reasonPhrase = statusline.getReasonPhrase();
        reasonCatalog = catalog;
        messageBody = responseBody;
        this.locale = locale;
    }

    /**
     * Constructor.
     * @param signatureParams
     * @param statusline
     * @param responseBody
     */
    public SignedHttpResponse(SignatureParameter signatureParams, final StatusLine statusline, String responseBody) {
        super(signatureParams);
        this.statusline = Args.notNull(statusline, "Status line");
        reasonCatalog = null;
        locale = null;
        messageBody = responseBody;

    }

    /**
     * Constructor.
     * @param signatureParams
     * @param statusline
     * @param responseBody
     * @param request
     */
    public SignedHttpResponse(SignatureParameter signatureParams, final StatusLine statusline, String responseBody,
            HttpRequest request) {
        super(signatureParams);
        this.statusline = Args.notNull(statusline, "Status line");
        reasonCatalog = null;
        locale = null;
        messageBody = responseBody;
        relatedRequest = request;

    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpMessage#getProtocolVersion()
     */
    @Override
    public ProtocolVersion getProtocolVersion() {
        return getStatusLine().getProtocolVersion();
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#getStatusLine()
     */
    @Override
    public StatusLine getStatusLine() {
        if (statusline == null) {
            statusline = new BasicStatusLine(version != null ? version : HttpVersion.HTTP_1_1, code,
                    reasonPhrase != null ? reasonPhrase : getReason(code));
        }

        return statusline;
    }

    /**
     * @param code
     * @return
     */
    private String getReason(int code) {
        return reasonCatalog != null ? reasonCatalog.getReason(code, locale != null ? locale : Locale.getDefault())
                : null;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setStatusLine(org.apache.http.StatusLine)
     */
    @Override
    public void setStatusLine(StatusLine statusline) {
        this.statusline = Args.notNull(statusline, "Status line");
        version = statusline.getProtocolVersion();
        code = statusline.getStatusCode();
        reasonPhrase = statusline.getReasonPhrase();

    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setStatusLine(org.apache.http.ProtocolVersion, int)
     */
    @Override
    public void setStatusLine(final ProtocolVersion ver, final int code) {
        Args.notNegative(code, "Status code");
        statusline = null;
        version = ver;
        this.code = code;
        reasonPhrase = null;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setStatusLine(org.apache.http.ProtocolVersion, int)
     */
    @Override
    public void setStatusLine(final ProtocolVersion ver, final int code, final String reason) {
        Args.notNegative(code, "Status code");
        statusline = null;
        version = ver;
        this.code = code;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setStatusCode(int)
     */
    @Override
    public void setStatusCode(int code) throws IllegalStateException {
        this.code = code;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setReasonPhrase(java.lang.String)
     */
    @Override
    public void setReasonPhrase(String reason) throws IllegalStateException {
        reasonPhrase = reason;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#getEntity()
     */
    @Override
    public HttpEntity getEntity() {

        return entity;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setEntity(org.apache.http.HttpEntity)
     */
    @Override
    public void setEntity(HttpEntity entity) {
        this.entity = entity;

    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#getLocale()
     */
    @Override
    public Locale getLocale() {
        return locale;
    }

    /** (non-Javadoc)
     * @see org.apache.http.HttpResponse#setLocale(java.util.Locale)
     */
    @Override
    public void setLocale(Locale loc) {
        locale = loc;

    }

    /**
     * @return realatedRequest
     */
    public HttpRequest getRelatedHttpRequest() {
        return relatedRequest;
    }

    /** (non-Javadoc)
     * @see signature.messages.SignedHttpMessage#setMessageBody(java.lang.String)
     */
    @Override
    void setMessageBody(String messageBody) {
        this.messageBody = messageBody;

    }

    /** (non-Javadoc)
     * @see signature.messages.SignedHttpMessage#getMessageBody()
     */
    @Override
    public String getMessageBody() {

        return messageBody;
    }

    /**
     * @return the relatedSingatureLabel
     */
    public List<String> getRelatedSingatureLabel() {
        return relatedSingatureLabel;
    }

    /**
     * @param relatedSingatureLabel the relatedSingatureLabel to set
     */
    public void setRelatedSingatureLabel(List<String> relatedSingatureLabel) {
        this.relatedSingatureLabel = relatedSingatureLabel;
    }

}
