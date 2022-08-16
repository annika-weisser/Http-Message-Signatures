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
package Exceptions;

/**
 * NoSuchSignatureException is thrown if there is no signature matching the signature label in the message
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 01.08.2022
 * @since PAS-X V3.2.4
 */
public class NoSuchSignatureException extends Exception {

    /**
     *
     * @param errorMessage
     */
    public NoSuchSignatureException(String errorMessage) {
        super(errorMessage);
    }
}
