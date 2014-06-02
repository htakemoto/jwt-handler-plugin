package com.htakemoto;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import net.oauth.jsontoken.JsonToken;

public class Application
{
	public static void main(String[] args) throws Exception {
		
		Map<String, String> map = new HashMap<String, String>();
        map.put("bar", "15");
        map.put("foo", "some value");
        map.put("email", "htakemoto@sample.ca");
		
		String jwt = JwtBuilder.generateJWT(map);
		System.out.println("JWT Encoding: " + jwt);
		
		try {
			JsonToken jsonToken = JwtBuilder.deserializeJWT(jwt);
			System.out.println("JWT Decoding: " + jsonToken.getPayloadAsJsonObject().toString());
		} catch (InvalidKeyException e) {
			System.err.println("Exception: "+e.getMessage()+" caused by: "+e.getCause());
		} catch (SignatureException e) {
			System.err.println("Exception: "+e.getMessage()+" caused by: "+e.getCause());
		}
	}
}
