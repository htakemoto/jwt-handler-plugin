package com.htakemoto;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.SystemClock;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.joda.time.Duration;

import com.google.common.collect.Lists;

public class JwtBuilder
{
	private static final byte[] SYMMETRIC_KEY = "kjdhasdkjhaskdjhaskdjhaskdjh".getBytes();
	private static final String ISSUER = "sample.ca";
	private static final int TOKEN_DURATION = 20; // minutes
	
	private static final Duration SKEW = Duration.standardMinutes(1);
	public static SystemClock clock = new SystemClock(SKEW);
	
	public static String generateJWT(Map<String, String> map) throws Exception {
		
		HmacSHA256Signer signer = new HmacSHA256Signer(ISSUER, "key1", SYMMETRIC_KEY);
	
		JsonToken token = new JsonToken(signer, clock);
		
        Iterator<Map.Entry<String, String>> iterator = map.entrySet().iterator();
        while(iterator.hasNext()){
            Map.Entry<String, String> entry = iterator.next();
            // check if value is Numeric so JWT Decoding format removes double quotations for the key
            if (JwtBuilder.isNumeric(entry.getValue()) && JwtBuilder.parseStringToNumber(entry.getValue()) != null) {
            	token.setParam(entry.getKey(), JwtBuilder.parseStringToNumber(entry.getValue()));
            }
            else {
            	token.setParam(entry.getKey(), entry.getValue());
            }
        }
        
		token.setIssuedAt(clock.now());
		token.setExpiration(clock.now().withDurationAdded(Duration.standardMinutes(TOKEN_DURATION), 1));
	
		return token.serializeAndSign();
	}
	
	
	public static JsonToken deserializeJWT(String tokenString) throws InvalidKeyException, SignatureException {
		final Verifier hmacVerifier = new HmacSHA256Verifier(SYMMETRIC_KEY);
		VerifierProvider hmacLocator = new VerifierProvider() {
	        @Override
	        public List<Verifier> findVerifier(String signerId, String keyId) {
	          return Lists.newArrayList(hmacVerifier);
	        }
	    };
	    VerifierProviders locators = new VerifierProviders();
	    locators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
		
	    JsonTokenParser parser = new JsonTokenParser(clock, locators, null);

//	    JsonToken token = parser.deserialize(tokenString);
	    
	    // verify exp time and SYMMETRIC_KEY etc.
	    JsonToken token = parser.verifyAndDeserialize(tokenString);
	    
	    return token;
	}
	
	private static boolean isNumeric(String inputData) {
		  return inputData.matches("[-+]?\\d+(\\.\\d+)?");
	}
	
	private static Number parseStringToNumber(String str) {
	    Number number = null;
	    try {
	    	number = Integer.parseInt(str);
	    } catch (NumberFormatException e) {
	    	try {
	    		number = Long.parseLong(str);
		    } catch (NumberFormatException e1) {
		    	try {
		    		number = Float.parseFloat(str);
			    } catch (NumberFormatException e2) {
			    	try {
			    		number = Double.parseDouble(str);
				    } catch (NumberFormatException e3) {
				    	
				    }
			    }
		    }
	    }
	    return number;
	}

}
