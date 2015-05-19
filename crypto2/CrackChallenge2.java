 /* SECURITY 2014-2015
  * Name(s) : Cas van der Weegen [2566388]
  * Study:    Computer Science
  * Course:   Security
  * Git: github.com/vdweegen
  *
  * Assignment: Challenge 2
  *
  * Compile: javac CrackChallenge2.java
  *
  * Usage:   java CrackChallenge2
  *
  *
  * Note: Unless instructed otherwise, this file shall be uploaded at the end
  *       of the college year 2014/2015
  */
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.*;

public class CrackChallenge2 {
	private static int m = Integer.MAX_VALUE; /* Modulo Value */
	private static int a = 16807; /* A */
	
    public static void main(String[] args) {
    	Path path = Paths.get("encrypted_mail.txt"); /* Load encrypted email  */
    	byte[] bytes = null; /* Initialize ByteArray that will hold the bytes */
    	try{                 /* of the encrypted file                         */
    		bytes = Files.readAllBytes(path);
    	}
    	catch(IOException e){ /* Catch Error */
    		System.out.println("Are you sure you have 'encrypted.txt'?");
    	}
    	
      byte[] b = new byte[4]; /* This one will contain our 'current encryption key' */
      /* Perform a XOR on the first four bytes */
      b[0] = (byte) ((bytes[0] ^ 'D') & 0xff);
      b[1] = (byte) ((bytes[1] ^ 'a') & 0xff);
      b[2] = (byte) ((bytes[2] ^ 't') & 0xff);
      b[3] = (byte) ((bytes[3] ^ 'e') & 0xff);
    	
    	/* Convert Bytes to Int */
    	int blocks = bytes.length/4;
    	int seed = byteToInt(b); /* Calculate the Initial Seed */
    	System.out.println("Seed value of First Block #1: "+seed);
    	String out = "";
    	
      /* Encrypt the file */
    	System.out.println("\nLength of Encrypted File: "+bytes.length+" has "+blocks+" blocks");
    	for(int i = 0; i < bytes.length/4; i++){
    		byte[] b2 = intToByte(seed);
    		System.out.println("\nDecrypting Block: "+i+"\tSeed: "+seed+"\t"+toBinary(b2));
    		for(int j = 0; j < 4; j++){
    			int res = (b2[j] ^ bytes[i*4+j]);
    			out += ""+(char)res;
    		}
    		seed = rng(seed); /* Calculate next seed */
    	}
    	System.out.println(out);
    }
    
    /* Contains are Random Number Generator */
    public static int rng(int seed){
    	int res = (seed * a) % m;
    	if(res < 0){ /* If negative, we overflowed... Correct output */
    		return (-(Integer.MAX_VALUE - ((seed * a) % m)));
    	}else{
    		return res;
    	}
    }
       
    /* Helper function that converts a byteArray to an Int (little endian) */
    public static int byteToInt(byte[] b){
    	return java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
    /* Helper function that converts an Int to a byteArray (little endian) */
    public static byte[] intToByte(int i){
    	byte[] ret = new byte[4];
        ret[0] = (byte) (i & 0xFF);
        ret[1] = (byte) ((i >> 8) & 0xFF);   
        ret[2] = (byte) ((i >> 16) & 0xFF);   
        ret[3] = (byte) ((i >> 24) & 0xFF);
        return ret;
    }
 
    /* Helper function to return the binary representation of a byteArray */
    public static String toBinary( byte[] bytes ){
        StringBuilder sb = new StringBuilder(bytes.length * Byte.SIZE);
        for( int i = 0; i < Byte.SIZE * bytes.length; i++ )
            sb.append((bytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
        return sb.toString();
    }
}