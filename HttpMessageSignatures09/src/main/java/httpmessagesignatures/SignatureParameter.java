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

import java.time.Instant;
import java.util.List;

/**
 * Contains the parameters bound to a signature (see 2.2.1. Signature Parameters).
 * The component covered by the signature are also considered as signature parameters.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 09.03.2022
 */
public class SignatureParameter {

    /**
     * Constructor.
     * @param algorithm Algorithm used for the signature.
     * @param keyId ID of the key used for the signature.
     * @param created Time of signature creation.
     * @param signLabel Label of the signature.
     * @param coveredHeaders List of component IDs covered by the signature.
     */
    public SignatureParameter(String algorithm, String keyId, String signLabel, List<Component> coveredHeaders) {

        this.algorithm = algorithm;
        this.keyId = keyId;
        created = Instant.now().getEpochSecond();
        nonce = null;
        this.signLabel = signLabel;
        this.coveredHeaders = coveredHeaders;

    }

    /**
     *
    * @param algorithm Algorithm used for the signature.
     * @param keyId ID of the key used for the signature.
     * @param created Time of signature creation.
      * @param expires at which the signature expires.
     * @param signLabel Label of the signature.
     * @param coveredHeaders List of component IDs covered by the signature.
     * @throws IllegalArgumentException
     */
    public SignatureParameter(String algorithm, String keyId, Long expires, String signLabel,
            List<Component> coveredHeaders) {

        this.algorithm = algorithm;
        this.keyId = keyId;
        created = Instant.now().getEpochSecond();
        nonce = null;
        this.signLabel = signLabel;
        this.coveredHeaders = coveredHeaders;
        if (expires != null) {
            if ((expires > created)) {
                this.expires = expires;
            } else {
                throw new IllegalArgumentException("expire time must be a time after created");
            }
        }

    }

    /**
     * Constructor.
     * @param algorithm Algorithm used for the signature.
     * @param keyId ID of the key used for the signature.
     * @param nonce Unique value against replay attack.
     * @param created Time of signature creation.
     * @param expires Time at which the signature expires.
     * @param signLabel Label of the signature.
     * @param coveredHeaders List of component IDs covered by the signature.
     * @throws IllegalArgumentException
     */
    public SignatureParameter(String algorithm, String keyId, String nonce, Long expires, String signLabel,
            List<Component> coveredHeaders) {

        this.algorithm = algorithm;
        this.keyId = keyId;
        created = Instant.now().getEpochSecond();

        this.signLabel = signLabel;
        this.coveredHeaders = coveredHeaders;
        if (expires != null) {
            if ((expires > created)) {
                this.expires = expires;
            } else {
                throw new IllegalArgumentException("expire time must be a time after created");
            }
        }

        if (nonce != null) {
            this.nonce = nonce;
        }
    }

    /**
     * Constructor.
     * @param algorithm Algorithm used for the signature.
     * @param keyId ID of the key used for the signature.
     * @param none Unique value against replay attack.
     * @param signLabel Label of the signature.
     * @param coveredHeaders List of component IDs covered by the signature.
     */
    public SignatureParameter(String algorithm, String keyId, String nonce, String signLabel,
            List<Component> coveredHeaders) {

        this.algorithm = algorithm;
        this.keyId = keyId;
        created = Instant.now().getEpochSecond();

        this.signLabel = signLabel;
        this.coveredHeaders = coveredHeaders;

        if (nonce != null) {
            this.nonce = nonce;
        }
    }

    /**
     * Creation time as an sf-integer UNIX timestamp value.
     * Specifies the time the signature was created.
     */
    private Long created;
    /**
     * Optional: Expires time as an sf-integer UNIX timestamp value.
     * Indicates when the signature will expire.
     */
    private Long expires;
    /**
     * Optional: A random unique value generated for this signature.
     */
    private String nonce = "";
    /**
     * The algorithm used for the HTTP message signature.
     */
    private String algorithm;
    /**
     * The identifier for the key material.
     */
    private String keyId;

    /**
     * Label of the signature.
     */
    private String signLabel;
    /**
     * List of component IDs covered by the signature.
     */
    private List<Component> coveredHeaders;

    /**
     * dnsTarget contains target IP-address.
     */
    private String dnsTarget;

    /**
     * @return the signLabel
     */
    public String getSignLabel() {
        return signLabel;
    }

    /**
     * @return the coveredHeaders
     */
    public List<Component> getCoveredHeaders() {
        return coveredHeaders;
    }

    /**
     * @return the created
     */
    public long getCreated() {
        return created;
    }

    //for Verifying
    protected void setCreated(long created) {
        this.created = created;
    }

    /**
     * @return the expires
     */
    public long getExpireTime() {
        return expires;
    }

    /**
     * @return the nonce
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the keyId
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * @return canonicalized value of the parameters
     */
    protected String createCanonicalizedValue() {
        String value = "";
        value = value + ";" + "created" + "=" + created;

        if (expires != null) {
            value = value + ";" + "expires" + "=" + expires;
        }

        value = value + ";" + "keyid" + "=" + "\"" + keyId + "\"" + ";" + "alg" + "=" + "\"" + algorithm + "\"";

        if (((nonce != null)) && (!nonce.isEmpty())) {
            value = value + ";" + "nonce" + "=" + "\"" + nonce + "\"";
        }
        if ((dnsTarget != null) && (!dnsTarget.isEmpty())) {
            value = value + ";" + "dns-target" + "=" + "\"" + dnsTarget + "\"";
        }

        return value;

    }

    /**
     * @return the dnsTarget
     */
    public String getDnsTarget() {
        return dnsTarget;
    }

    /**
     * @param dnsTarget the dnsTarget to set
     */
    protected void setDnsTarget(String dnsTarget) {
        this.dnsTarget = dnsTarget;
    }

}
