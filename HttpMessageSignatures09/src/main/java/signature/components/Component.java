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
package signature.components;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

/**
 * Class for specifying the components of the signature that are included in the signature base.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 05.08.2022
 * @since PAS-X V3.2.4
 */
public class Component {

    /** ID of the message component. */
    private String componentId;
    /** Messages component parameters. */
    private NameValuePair[] parameters;
    /** Req-flag for request-response binding. */
    private boolean req;
    /** Value of the component. */
    private String value;

    public Component(String componentId, NameValuePair parameter, boolean req) {
        this.componentId = componentId;

        this.req = req;
        if (req) {
            parameters = new NameValuePair[] {new BasicNameValuePair("req", null), parameter};
        } else {
            parameters = new NameValuePair[] {parameter};
        }
    }

    public Component(String componentId) {
        this.componentId = componentId;
        parameters = null;
        req = false;
    }

    public Component(String componentId, boolean req) {
        this.componentId = componentId;
        this.req = req;
        if (req) {
            parameters = new NameValuePair[] {new BasicNameValuePair("req", null)};
        }

    }

    /**
     * @return the componentId
     */
    public String getComponentId() {
        return componentId;
    }

    /**
     * @return the parameter
     */
    public NameValuePair[] getParameter() {
        return parameters;
    }

    /**
     * @return the req
     */
    public boolean isReq() {
        return req;
    }

    /**
     * @return the value
     */
    public String getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(String value) {
        this.value = value;
    }

}
