package com.sankidev.sign.payload;

import java.awt.Checkbox;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SignPayloadApplication {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, IOException {
	//openssl commands
//		openssl genrsa -out keypair.pem 2048
//
//		openssl rsa -in keypair.pem -pubout -out publickey.crt
//
//		openssl pkcs8 -topk8 -inform PEM -outform DER -in keypair.pem -out key2.pem -nocrypt
		
		check();
		SpringApplication.run(SignPayloadApplication.class, args);
	}
	
	
	public static void check() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
		String message = "no";
		File privateKeyFile  = new File("C:\\work\\Defi work\\sign_payload\\keys\\key2.pem");
		DataInputStream dis = new DataInputStream(new FileInputStream(privateKeyFile));
        byte[] privKeyBytes = new byte[(int)privateKeyFile.length()];
        dis.read(privKeyBytes);
        dis.close();
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);        
	    byte[] sign = signMessage(message.getBytes(), privKey);
        System.out.println("sign  : ");
	    System.out.println(sign);
	    System.out.println("sign 2 ");
	    String keyAsString = Base64.getEncoder().encodeToString(sign);
	    System.out.println(keyAsString);
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
        	  RSAPublicKey pubKey = (RSAPublicKey) fact.generatePublic(pubKeySpec);
		
        System.out.println("--- Example with a valid signature ---");
        validateMessageSignature(pubKey, "no".getBytes(), sign);
		
	}
	
    public static byte[] signMessage(byte[] message,PrivateKey privateKey) throws NoSuchAlgorithmException,
    InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
     
        Signature sig = Signature.getInstance("SHA256withRSA");
        
         // Signature sig = Signature.getInstance("RSA");
          sig.initSign(privateKey);
          sig.update(message);
          byte[] sign= sig.sign();
          return sign;
    }
    
    public static void validateMessageSignature(PublicKey publicKey, byte[] message, byte[] signature) throws
    NoSuchAlgorithmException, InvalidKeyException, SignatureException {
   
    	  Signature clientSig = Signature.getInstance("SHA256withRSA");
         // verifier.initVerify(publicKey);
    	//Signature clientSig = Signature.getInstance("RSA");
    clientSig.initVerify(publicKey);
    clientSig.update(message);
    if (clientSig.verify(signature)) {
       System.out.println("The message is properly signed.");
    } else {
       System.err.println("It is not possible to validate the signature.");
    }
}

}
