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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHttpResponse;

/**
 * Provides example request/response for the test classes.
 *
 * @author annika_weisser
 * @company Koerber Pharma Software GmbH
 * @created 29.07.2022
 * @since PAS-X V3.2.4
 */
public class TestMessagProvider {

    public static HttpPost getTestRequest() throws URISyntaxException, UnsupportedEncodingException {

        URI uri = new URI("//example.com/foo?param=Value&Pet=dog");
        HttpPost postRequest = new HttpPost(uri);
        postRequest.setProtocolVersion(HttpVersion.HTTP_1_1);
        postRequest.addHeader("Host", "example.com");
        postRequest.addHeader("Date", "Tue, 20 Apr 2021 02:07:55 GMT");
        postRequest.addHeader("Content-Type", "application/json");
        postRequest.addHeader("Content-Digest",
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:");
        postRequest.addHeader("Content-Length", "18");
        String body = "{\"hello\": \"world\"}";
        StringEntity entity = new StringEntity(body);
        postRequest.setEntity(entity);
        return postRequest;

    }

    public static HttpResponse getResponse() throws URISyntaxException, UnsupportedEncodingException {

        HttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_1, 200, "OK");
        response.addHeader("Date", "Tue, 20 Apr 2021 02:07:56 GMT");
        response.addHeader("Content-Type", "application/json");
        response.addHeader("Content-Digest",
                "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:");
        response.addHeader("Content-Length", "23");
        String body = "{\"message\": \"good dog\"}";
        StringEntity entity = new StringEntity(body);
        response.setEntity(entity);

        return response;
    }
}
