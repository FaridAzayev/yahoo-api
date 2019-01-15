package com.azayev.java.yahoo.api;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Random;
import java.util.Collections;
import java.net.URLEncoder;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;


import java.net.URI;

public class Weather {

    public static void main(String[] args) throws Exception {

        final String appId = "dSRg8p54";
        final String consumerKey = "dj0yJmk9R2Q3Z1JZdGJNZTJWJnM9Y29uc3VtZXJzZWNyZXQmc3Y9MCZ4PWYw";
        final String consumerSecret = "9b61554ff2b4529729e319bb8fc209dbb0ad1cb9";
        final String url = "https://weather-ydn-yql.media.yahoo.com/forecastrss";

        long timestamp = new Date().getTime() / 1000;
        byte[] nonce = new byte[32];
        Random rand = new Random();
        rand.nextBytes(nonce);
        String oauthNonce = new String(nonce).replaceAll("\\W", "");

        List<String> parameters = new ArrayList<>();
        parameters.add("oauth_version=1.0");
        parameters.add("oauth_signature_method=HMAC-SHA1");
        parameters.add("oauth_consumer_key=" + consumerKey);
        parameters.add("oauth_nonce=" + oauthNonce);
        parameters.add("oauth_timestamp=" + timestamp);
        // Make sure value is encoded
        parameters.add("location=" + URLEncoder.encode("sunnyvale,ca", "UTF-8"));
        parameters.add("format=json");
        Collections.sort(parameters);

        StringBuffer parametersList = new StringBuffer();
        for (int i = 0; i < parameters.size(); i++) {
            parametersList.append(((i > 0) ? "&" : "") + parameters.get(i));
        }

        String signatureString = "GET&" +
                URLEncoder.encode(url, "UTF-8") + "&" +
                URLEncoder.encode(parametersList.toString(), "UTF-8");

        String signature = null;

        String algorithm = "HmacSHA1";

        try {
            SecretKeySpec signingKey = new SecretKeySpec((consumerSecret + "&").getBytes(), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(signingKey);
            byte[] rawHMAC = mac.doFinal(signatureString.getBytes());
            Encoder encoder = Base64.getEncoder();
            signature = encoder.encodeToString(rawHMAC);
        } catch (Exception e) {
            System.err.println("Unable to append getSignature");
            System.exit(0);
        }

        String authorizationLine = "OAuth " +
                "oauth_consumer_key=\"" + consumerKey + "\", " +
                "oauth_nonce=\"" + oauthNonce + "\", " +
                "oauth_timestamp=\"" + timestamp + "\", " +
                "oauth_signature_method=\"HMAC-SHA1\", " +
                "oauth_signature=\"" + signature + "\", " +
                "oauth_version=\"1.0\"";


        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(URI.create(url + "?location=sunnyvale,ca&format=json"));
        request.addHeader("Authorization", authorizationLine);
        request.addHeader("Yahoo-App-Id", appId);
        request.addHeader("Content-Type", "application/json");

        HttpResponse response = client.execute(request);

        System.out.println("Response Code : "
                + response.getStatusLine().getStatusCode());

        BufferedReader rd = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent()));

        StringBuffer result = new StringBuffer();
        String line = "";
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }

        System.out.println(result);
    }
}