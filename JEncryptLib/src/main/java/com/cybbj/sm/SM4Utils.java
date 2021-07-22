package com.cybbj.sm;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.cybbj.base64.Base64Util;

public class SM4Utils{
	public static String secretKey = "";
	public static String iv = "";
	public static boolean hexString = false;
	
	public SM4Utils(){
	}
	
	public static String encryptData_ECB(String plainText) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = true;
		ctx.mode = SM4.SM4_ENCRYPT;
		
		byte[] keyBytes;
		if (hexString){
			keyBytes = Util.hexStringToBytes(secretKey);
			System.out.println("keyBytes:"+secretKey);
		}
		else{
			keyBytes = secretKey.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_enc(ctx, keyBytes);
		byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
		System.out.println("hex encrypted: " + Util.byteToHex(encrypted));
		//String cipherText = new BASE64Encoder().encode(encrypted);
		String cipherText = new String(Base64Util.base64Encode(encrypted),"UTF-8");
		if (cipherText != null && cipherText.trim().length() > 0){
			Pattern p = Pattern.compile("\\s*|\t|\r|\n");
			Matcher m = p.matcher(cipherText);
			cipherText = m.replaceAll("");
		}
		return cipherText;
	}
	
	public static String decryptData_ECB(String cipherText) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = true;
		ctx.mode = SM4.SM4_DECRYPT;
		
		byte[] keyBytes;
		if (hexString){
			keyBytes = Util.hexStringToBytes(secretKey);
		}
		else{
			keyBytes = secretKey.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_dec(ctx, keyBytes);
		byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64Util.base64Decode(cipherText.getBytes("UTF-8")));
		//byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
		return new String(decrypted, "UTF-8");
	}
	
	public static String encryptData_CBC(String plainText) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = true;
		ctx.mode = SM4.SM4_ENCRYPT;
		
		byte[] keyBytes;
		byte[] ivBytes;
		if (hexString){
			System.out.println("secretKey hexString:"+Util.getHexString(secretKey.getBytes()));
			keyBytes = Util.hexStringToBytes(secretKey);
			ivBytes = Util.hexStringToBytes(iv);
		}
		else{
			keyBytes = secretKey.getBytes();
			ivBytes = iv.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_enc(ctx, keyBytes);
		byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("UTF-8"));
		System.out.println("hex encrypted: " + Util.byteToHex(encrypted));
		//String cipherText = new BASE64Encoder().encode(encrypted);
		String cipherText =new String(Base64Util.base64Encode(encrypted),"UTF-8");
		if (cipherText != null && cipherText.trim().length() > 0){
			Pattern p = Pattern.compile("\\s*|\t|\r|\n");
			Matcher m = p.matcher(cipherText);
			cipherText = m.replaceAll("");
		}
		return cipherText;
	}
	
	public static String decryptData_CBC(String cipherText) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = true;
		ctx.mode = SM4.SM4_DECRYPT;
		
		byte[] keyBytes;
		byte[] ivBytes;
		if (hexString){
			keyBytes = Util.hexStringToBytes(secretKey);
			ivBytes = Util.hexStringToBytes(iv);
		}
		else{
			keyBytes = secretKey.getBytes();
			ivBytes = iv.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_dec(ctx, keyBytes);
		//byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
		byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Base64Util.base64Decode(cipherText.getBytes("UTF-8")));
		return new String(decrypted, "UTF-8");
	}
	
	public static void main(String[] args) throws Exception{
		
		System.out.println("sm4 算法验证 ");
		String plainText = "1234";
		System.out.println("明文: " + plainText);
		SM4Utils sm4 = new SM4Utils();
		String key= "0123456789ABCDEFFEDCBA9876543210";
		//String hexStr= Util.getHexString(key.getBytes());
		//System.out.println("sm4 原始 :"+key);
		System.out.println("sm4 密钥 hex :"+key);
		sm4.secretKey = key;
		//System.out.println("secretKey: " + sm4.secretKey);
		//sm4.
		sm4.hexString = true;
		/*System.out.println("secretKey:JeF8U9wHFOMfs2Y8");
		System.out.println("ECB模式");
		String cipherText = sm4.encryptData_ECB(plainText);
		System.out.println("密文: " + cipherText);
		System.out.println("");
		plainText = sm4.decryptData_ECB(cipherText);
		System.out.println("解密后明文：" + plainText);
		System.out.println("CBC模式");
		String iv="UISwD9fW6cFh9SNS";
		String ivhexStr= Util.getHexString(iv.getBytes());*/
		
		
		sm4.iv = "00000000000000000000000000000000";
		System.out.println("CBC模式 sm4.iv:"+sm4.iv);
	    String	cipherText = sm4.encryptData_CBC(plainText);
		System.out.println("密文: " + cipherText);
		//System.out.println("");
		plainText = sm4.decryptData_CBC(cipherText);
		System.out.println("解密: " + plainText);
		
	}
}
