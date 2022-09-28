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

import org.apache.http.message.AbstractHttpMessage;

import signature.components.SignatureParameter;

/**
 * SignedHttpMessage contains attributes of a signed message.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 23.05.2022
 */
public abstract class SignedHttpMessage extends AbstractHttpMessage {

    /** signature parameter: contain all parameters belonging to the signature */
    protected SignatureParameter signatureParams;
    /** signature of the message */
    private String signature;
    /** signature-input values */
    private String signatureInput;
    /** signaturebase */
    private String signatureBase;
    /** message body */
    public String messageBody;

    /**
     * Constructor.
     * @param signatureParams
     */
    public SignedHttpMessage(SignatureParameter signatureParams) {
        super();
        this.signatureParams = signatureParams;
    }

    /**
     * @return the signatureParams
     */
    public SignatureParameter getSignatureParams() {
        return signatureParams;
    }

    /**
     * @param signature
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * @return the signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @param signatureInput
     */
    public void setSignatureInput(String signatureInput) {
        this.signatureInput = signatureInput;
    }

    /**
     * @return the signatureInput
     */
    public String getSignatureInput() {
        return signatureInput;
    }

    /**
     * @param signatureBase
     */
    public void setSignatureBase(String signatureBase) {
        this.signatureBase = signatureBase;
    }

    /**
     * @return the signatureBase
     */
    public String getSignatureBase() {
        return signatureBase;
    }

    /**
     * @param messageBody
     */
    abstract void setMessageBody(String messageBody);

    /**
     * @return the messageBody
     */
    public abstract String getMessageBody();

}
