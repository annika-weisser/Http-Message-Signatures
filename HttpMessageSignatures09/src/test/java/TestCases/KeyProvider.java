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
package TestCases;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;

/**
 * Provides the signature keys for the test classes.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 25.04.2022
 */
public class KeyProvider {

    public static byte[] getRsaPssPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        String privateKey = "MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv\r\n"
                + "P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5\r\n"
                + "3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr\r\n"
                + "FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA\r\n"
                + "AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw\r\n"
                + "9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy\r\n"
                + "c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq\r\n"
                + "pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X\r\n"
                + "aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4\r\n"
                + "XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ\r\n"
                + "HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD\r\n"
                + "2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N\r\n"
                + "RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx\r\n"
                + "DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6\r\n"
                + "vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm\r\n"
                + "rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi\r\n"
                + "4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL\r\n"
                + "FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/\r\n"
                + "OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx\r\n"
                + "NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR\r\n"
                + "NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ\r\n"
                + "3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE\r\n"
                + "t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND\r\n"
                + "dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF\r\n"
                + "S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR\r\n" + "rOjr9w349JooGXhOxbu8nOxX";

        privateKey = privateKey.replaceAll(System.lineSeparator(), "");

        return Base64.decodeBase64(privateKey);

    }

    public static byte[] getRsaPssPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {

        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI2wIDAQAB";
        return Base64.decodeBase64(publicKey);

    }

    public static byte[] getPublicEccKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==";
        return Base64.decodeBase64(publicKey);

    }

    public static byte[] getSharedSecret() throws NoSuchAlgorithmException, InvalidKeyException {
        String secret = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt\\\r\n"
                + "bmHhIDi6pcl8jsasjlTMtDQ==";
        secret = secret.replaceAll(System.lineSeparator(), "");

        return Base64.decodeBase64(secret);

    }

    public static byte[] getPrivateEccKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {

        String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgUpuF81l+kOxbjf7T"
                + "4mNSv0r5tN67Gim7rnf6EFpcYDugCgYIKoZIzj0DAQehRANCAASohVhlUsKs9kcY"
                + "eM/XsJNbT/4P0t/DQSSOoXvEHgWK8DHOJzfS0wzgYX6FHoPGHvVnnRUYZ2V2SQNd" + "kKdM2ehd";
        privateKey = privateKey.replaceAll(System.lineSeparator(), "");

        return Base64.decodeBase64(privateKey);

    }

    public static byte[] getEd25519PrivateKey() {
        String privateKey = "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF";

        return Base64.decodeBase64(privateKey);
    }

    public static byte[] getEd25519PublicKey() {
        String publicKey = "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";

        return Base64.decodeBase64(publicKey);
    }
}
