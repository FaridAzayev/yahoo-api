package com.azayev.groovy.yahoo.api

import org.apache.http.HttpResponse
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class Weather {
    static void main(String[] args) {
        final String url            = "https://weather-ydn-yql.media.yahoo.com/forecastrss"
        //get your id by registering your app at developer.yahoo.com
        final String appId          = "dSRg8p54"
        final String consumerKey    = "dj0yJmk9R2Q3Z1JZdGJNZTJWJnM9Y29uc3VtZXJzZWNyZXQmc3Y9MCZ4PWYw"
        final String consumerSecret = "9b61554ff2b4529729e319bb8fc209dbb0ad1cb9"
        long timestamp              = new Date().getTime() / 1000

        String oauthNonce = getNonce()

        String location   = URLEncoder.encode("sunnyvale,ca", "UTF-8")
        String version    = "1.0"
        String format     = "json"
        String algorithm  = "HmacSHA1"
        String algoParam  = "HMAC-SHA1"

        String parameters = URLEncoder.encode("format=$format&location=$location&oauth_consumer_key=$consumerKey" +
                "&oauth_nonce=$oauthNonce&oauth_signature_method=$algoParam&oauth_timestamp=$timestamp&oauth_version=$version"
                , "UTF-8")

        String signatureString = "GET&${URLEncoder.encode(url, "UTF-8")}&$parameters"

        String signature = getSignature((consumerSecret + "&").getBytes(), signatureString, algorithm)

        String authorizationLine = "OAuth oauth_consumer_key=\"$consumerKey\",oauth_nonce=\"$oauthNonce\"," +
                "oauth_timestamp=\"$timestamp\",oauth_signature_method=\"$algoParam\"," +
                "oauth_signature=\"$signature\",oauth_version=\"$version\""

        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(URI.create(url + "?location=sunnyvale,ca&format=json"))
        request.addHeader("Authorization", authorizationLine)
        request.addHeader("Yahoo-App-Id", appId)
        request.addHeader("Content-Type", "application/json")

        HttpResponse response = client.execute(request)

        println "Response Code : ${response.getStatusLine().getStatusCode()}"

        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()))

        StringBuffer result = new StringBuffer();
        String line = ""
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }

        System.out.println(result);
    }

    static String getSignature(byte[] bytes, String signatureString, String algorithm){
        try {
            SecretKeySpec signingKey = new SecretKeySpec(bytes, algorithm)
            Mac mac = Mac.getInstance(algorithm)
            mac.init(signingKey);
            byte[] rawHMAC = mac.doFinal(signatureString.getBytes())
            Base64.Encoder encoder = Base64.getEncoder()
            return encoder.encodeToString(rawHMAC)
        } catch (Exception e) {
            println e.stackTrace
        }
    }

    static String getNonce(){
        byte[] nonce = new byte[32]
        Random rand = new Random()
        rand.nextBytes(nonce)
        return new String(nonce).replaceAll("\\W", "")
    }
}
