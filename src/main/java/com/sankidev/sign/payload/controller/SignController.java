package com.sankidev.sign.payload.controller;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.node.ObjectNode;

@RestController
public class SignController {

	@GetMapping
	public String hello() {
		return "hello";
	}
	
	@PostMapping("/create-sign")
	public String createSign(@RequestBody String input) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
		File privateKeyFile  = new File("C:\\work\\Defi work\\sign_payload\\keys\\key2.pem");
		DataInputStream dis = new DataInputStream(new FileInputStream(privateKeyFile));
        byte[] privKeyBytes = new byte[(int)privateKeyFile.length()];
        dis.read(privKeyBytes);
        dis.close();
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(input.getBytes());
        byte[] signedPayload = signature.sign();
       
        String signAsString = Base64.getEncoder().encodeToString(signedPayload);
        
        System.out.println(signAsString);
        return signAsString;
	}
	
	@GetMapping("/validate-sign")
	public boolean validateSign(@RequestBody String sign) throws SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException {
		
		//input and sign
		String input = "Hello";
//		 // read public key DER file
//		File pubKeyFile  = new File("C:\\work\\Defi work\\sign_payload\\keys\\publickey.crt");
//        DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
//        byte[] pubKeyBytes = new byte[(int)pubKeyFile.length()];
//        dis.readFully(pubKeyBytes);
//        dis.close();
        
//		  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//	        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
//	        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
//	      
		
//		Signature verifier = Signature.getInstance("SHA256withRSA");
//        verifier.initVerify(pubKey);
//        verifier.update(input.getBytes());
//        boolean verified = verifier.verify(sign.getBytes());
        
		//read public key from file system
//		String publicKeyStr = new String(Files.readAllBytes(Paths.get("C:\\work\\Defi work\\sign_payload\\keys\\publickey.crt")));
//		
//        System.out.println("public key");
//        System.out.println(publicKeyStr);
		
        //decode keys 1
//        String publicKeyPem = publicKeyAsString
//        	    .replace("-----BEGIN PUBLIC KEY-----", "")
//        	    .replaceAll("\\n", "")
//        	    .replace("-----END PUBLIC KEY-----", "");
//System.out.println("after removal keys");
//System.out.println(publicKeyPem);
//        	byte[] keyContentAsBytes =  Base64.getDecoder().decode(publicKeyPem.trim());
//        
        
//        String publicKeyAsString = new String(Base64.getUrlDecoder().decode(publicKeyStr));
//        	System.out.println("key again");
//        	System.out.println(publicKeyAsString);
//        //decode keys 2
		String publicKeyAsString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw51WSmfnaOV6UIM1epvx"
				+ "btbddU/swcPYnLjMqpIpZMxUXOxUZk6ErOK9CzVySpEDH/Gpnm74Na1fZFJv898m"
				+ "ZVTNS+XGZxe8S9l78WIqdhhDKUN1dpC7kkhKtcin7aZ+STab6HTyKsf7WhfeKtj3"
				+ "aGQFF26976T6h43m1lSUHhkEYjg8HJ7vYqg+jEqNRkeqc/yknsJGrcG7lqJ5gmrq"
				+ "e1Ys/9pW5Dpv8UER2jDTihPyv31K+XKF2rxRud0+rbkjAd+zV3MghgZNeHBDlgc2"
				+ "P+qKIlMIpBfF+5VdVzVh2HGALAbi74nBgrVmShISYwCUE7X3rZ0BbkOwvfvDGUyn"
				+ "0wIDAQAB";
       byte[] keyContentAsBytes = Base64.getDecoder().decode(publicKeyAsString);
        	
        	
        	KeyFactory fact = KeyFactory.getInstance("RSA");
        	  X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyContentAsBytes);
        	  RSAPublicKey publicKey = (RSAPublicKey) fact.generatePublic(pubKeySpec);
		
        	  byte[] signBytes = Base64.getDecoder().decode(sign);
        	  Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(input.getBytes());
            boolean verified = verifier.verify(signBytes);
           
        return verified;
	}
}
