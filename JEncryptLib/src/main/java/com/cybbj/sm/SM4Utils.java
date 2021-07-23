package com.cybbj.sm;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.cybbj.base64.Base64Util;
import com.cybbj.contants.CommonContants;
import com.cybbj.util.Converts;

/**
 * 补位使用了 PKCS7Padding
 * iv使用了00000000000000000000000000000000
 * @author zengqiaowang
 *
 */
public class SM4Utils{
	//public static String secretKey = "";
	private static String iv = "00000000000000000000000000000000";
	//private static boolean hexString = true;
	public SM4Utils(){
	}
	
	/**
	 * ECB模式加密数据
	 * @param plainText	待加密数据
	 * @param secretKey	加密key
	 * @param contentIsHex	待加密数据是否为HEX格式
	 * @param keyIsHex	key是否为HEX格式
	 * @param isPadding 是否需要补位 true/false
	 * @return base64编码后的数据
	 */
	public static String encryptData_ECB(String plainText,String secretKey,boolean contentIsHex,boolean keyIsHex,boolean isPadding) throws Exception{
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_ENCRYPT;
		
		byte[] keyBytes;
		if (keyIsHex){
			keyBytes = Util.hexStringToBytes(secretKey);
		} else{
			keyBytes = secretKey.getBytes();
		}
		
		byte[] contentBytes;
		if (contentIsHex) {
			contentBytes = Util.hexStringToBytes(plainText);
		} else {
			contentBytes = plainText.getBytes(CommonContants.DEFAULT_CHARACTER);
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_enc(ctx, keyBytes);
		byte[] encrypted = sm4.sm4_crypt_ecb(ctx,contentBytes);
		System.out.println("hex encrypted: " + Util.byteToHex(encrypted));
		//String cipherText = new String(SecureUtil.base64Encode(encrypted),CommonContants.DEFAULT_CHARACTER);
		String cipherText = new String(Base64Util.base64Encode(encrypted),CommonContants.DEFAULT_CHARACTER);
		if (cipherText != null && cipherText.trim().length() > 0){
			Pattern p = Pattern.compile("\\s*|\t|\r|\n");
			Matcher m = p.matcher(cipherText);
			cipherText = m.replaceAll("");
		}
		return cipherText;
		
	}
	
	/**
	 * ECB模式解密数据
	 * @param cipherText   base64编码
	 * @param secretKey
	 * @param keyIsHex
	 * @param isPadding 是否需要补位 true/false
	 * @return
	 */
	public static String decryptData_ECB(String cipherText,String secretKey,boolean keyIsHex,boolean isPadding) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_DECRYPT;
		
		byte[] keyBytes;
		if (keyIsHex){
			keyBytes = Util.hexStringToBytes(secretKey);
		}
		else{
			keyBytes = secretKey.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_dec(ctx, keyBytes);
		//byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
		byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64Util.base64Decode(cipherText.getBytes(CommonContants.DEFAULT_CHARACTER)));
		return new String(decrypted, CommonContants.DEFAULT_CHARACTER);
	}
	
	/**
	 * ECB模式解密数据
	 * @param cipherText   base64编码
	 * @param secretKey
	 * @param keyIsHex
	 * @param isPadding 是否需要补位 true/false
	 * @return
	 */
	public static byte[] decryptData_ECB2(String cipherText,String secretKey,boolean keyIsHex,boolean isPadding) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_DECRYPT;
		
		byte[] keyBytes;
		if (keyIsHex){
			keyBytes = Util.hexStringToBytes(secretKey);
		}
		else{
			keyBytes = secretKey.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_dec(ctx, keyBytes);
		//byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
		byte[] decrypted = sm4.sm4_crypt_ecb(ctx,Base64Util.base64Decode(cipherText.getBytes(CommonContants.DEFAULT_CHARACTER)));
		return decrypted;
	}
	
	/**
	 * CBC模式加密数据
	 * @param plainText	待加密数据
	 * @param secretKey	加密key
	 * @param contentIsHex	待加密数据是否为HEX格式
	 * @param keyIsHex	key是否为HEX格式
	 * @param isPadding 是否需要补位 true/false
	 * @return base64编码后的数据
	 * 
	 */
	public static String encryptData_CBC(String plainText,String secretKey,boolean contentIsHex,boolean keyIsHex,boolean isPadding)throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_ENCRYPT;
		
		byte[] keyBytes;
		byte[] ivBytes;
		if (keyIsHex){
			keyBytes = Util.hexStringToBytes(secretKey);
			ivBytes = Util.hexStringToBytes(iv);
		}
		else{
			keyBytes = secretKey.getBytes();
			ivBytes = iv.getBytes();
		}
		
		byte[] contentBytes;
		if (contentIsHex) {
			contentBytes = Util.hexStringToBytes(plainText);
		} else {
			contentBytes = plainText.getBytes(CommonContants.DEFAULT_CHARACTER);
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_enc(ctx, keyBytes);
		byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, contentBytes);
		System.out.println("hex encrypted: " + Util.byteToHex(encrypted));
		//String cipherText =new String(SecureUtil.base64Encode(encrypted),CommonContants.DEFAULT_CHARACTER);
		String cipherText =new String(Base64Util.base64Encode(encrypted),CommonContants.DEFAULT_CHARACTER);
		if (cipherText != null && cipherText.trim().length() > 0){
			Pattern p = Pattern.compile("\\s*|\t|\r|\n");
			Matcher m = p.matcher(cipherText);
			cipherText = m.replaceAll("");
		}
		return cipherText;
	}
	
	/**
	 * CBC模式加密数据
	 * @param bt	待加密数据
	 * @param secretKey	加密key
	 * @param keyIsHex	key是否为HEX格式
	 * @param isPadding 是否需要补位 true/false
	 * @return base64编码后的数据
	 * 
	 */
	public static String encryptData_CBC(byte[] bt ,String secretKey,boolean keyIsHex,boolean isPadding) throws Exception{
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_ENCRYPT;
		
		byte[] keyBytes;
		byte[] ivBytes;
		if (keyIsHex){
			keyBytes = Util.hexStringToBytes(secretKey);
			ivBytes = Util.hexStringToBytes(iv);
		}
		else{
			keyBytes = secretKey.getBytes();
			ivBytes = iv.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_enc(ctx, keyBytes);
		byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, bt);
		//System.out.println("hex encrypted: " + Util.byteToHex(encrypted));
		//String cipherText =new String(SecureUtil.base64Encode(encrypted),CommonContants.DEFAULT_CHARACTER);
		String cipherText =new String(Base64Util.base64Encode(encrypted),CommonContants.DEFAULT_CHARACTER);
		if (cipherText != null && cipherText.trim().length() > 0){
			Pattern p = Pattern.compile("\\s*|\t|\r|\n");
			Matcher m = p.matcher(cipherText);
			cipherText = m.replaceAll("");
		}
		return cipherText;
	}
	
	/**
	 * CBC模式解密数据
	 * @param cipherText base64编码
	 * @param secretKey
	 * @param keyIsHex
	 * @param isPadding 是否需要补位 true/false
	 * @return String
	 */
	public static String decryptData_CBC(String cipherText,String secretKey,boolean keyIsHex,boolean isPadding) throws Exception {
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_DECRYPT;
		
		byte[] keyBytes;
		byte[] ivBytes;
		if (keyIsHex){
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
		byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes,Base64Util.base64Decode(cipherText.getBytes(CommonContants.DEFAULT_CHARACTER)));
		return new String(decrypted, CommonContants.DEFAULT_CHARACTER);
	}
	
	/**
	 * CBC模式解密数据
	 * @param cipherText base64编码
	 * @param secretKey
	 * @param keyIsHex
	 * @param isPadding 是否需要补位 true/false
	 * @return byte[]
	 */
	public static byte[] decryptData_CBC2(String cipherText,String secretKey,boolean keyIsHex,boolean isPadding) throws Exception{
		byte[] decrypted = null;
		SM4_Context ctx = new SM4_Context();
		ctx.isPadding = isPadding;
		ctx.mode = SM4.SM4_DECRYPT;
		
		byte[] keyBytes;
		byte[] ivBytes;
		if (keyIsHex){
			keyBytes = Util.hexStringToBytes(secretKey);
			ivBytes = Util.hexStringToBytes(iv);
		}
		else{
			keyBytes = secretKey.getBytes();
			ivBytes = iv.getBytes();
		}
		
		SM4 sm4 = new SM4();
		sm4.sm4_setkey_dec(ctx, keyBytes);
		//log.debug("base64 decode: " + new BASE64Decoder().decodeBuffer(cipherText));
		//decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
		decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes,Base64Util.base64Decode(cipherText.getBytes(CommonContants.DEFAULT_CHARACTER)));
		return decrypted;
	}
	
	public static void main(String[] args) throws Exception{
		
		System.out.println("sm4 算法验证 ");
		//System.out.println("明文: " + plainText);
		String plainText = "06123456FFFFFFFFFFFFFE9CAA9BFD68";
		String key= "F41F57C3E54413309ECFA8439D2FBA49";
		/*String plainText = "CF69FF6EACDEC9DDBAC29F68BA27AF968678F51F2C9912C29F84B720522E2657995508A0C77721160A5C62FEEB114CAD2E613CCB0BC4CF86D6B72F6BD74213FD";
		String key= "52A832485BC8743852A832485BC87438";*/

		/*System.out.println("ECB模式");
		String cipherText = SM4Utils.encryptData_ECB(plainText,key,true,true,false);
		System.out.println("密文: " + cipherText);
		byte[] plainBt = SM4Utils.decryptData_ECB2(cipherText,key,true,false);		
		System.out.println("解密: " + Util.byteToHex(plainBt));*/
		
		//sm4.iv = "00000000000000000000000000000000";
		System.out.println("CBC模式");
		long startTime = System.currentTimeMillis();
	    String cipherText = SM4Utils.encryptData_CBC(plainText,key,true,true,true);
		//String cipherText = "zY3kI44S3VFzXZtvpzKw8g==";
	    System.out.println("加密：" + cipherText);
	    System.out.println("加密时间：" + (System.currentTimeMillis()-startTime));
		byte[] plainBt = SM4Utils.decryptData_CBC2(cipherText,key,true,true);
		//byte[] plainBt = SM4Utils.decryptData_CBC2("3uuPND0RXc/2qNvYkMTsJMJT/o2CGbVeu61uZ1g9OfE=",key,true,false);
		System.out.println("解密: " + Converts.bytesToHexString(plainBt));
		
		//测试随机生成密钥
		//String randomKey = RandomStringUtils.randomAlphanumeric(16);
		//System.out.println("随机数：" + randomKey + "\tHEX: " + Util.byteToHex(randomKey.getBytes(CommonContants.DEFAULT_CHARACTER)));
	}
}
