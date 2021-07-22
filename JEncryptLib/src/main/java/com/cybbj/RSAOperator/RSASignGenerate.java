package com.cybbj.RSAOperator;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.cybbj.base64.Base64Util;
public class RSASignGenerate {

	/**
	 * 签名(明文SHA-256计算摘要，然后对摘要进行签名，签名算法：SHA256withRSA)
	 * 
	 * @param privateKeyStr    私钥
	 * @param plain_text	明文
	 * @return	Base64编码签名之后的数据
	 * @throws Exception 
	 */
	public static String signBySHA256withRSA(String privateKeyStr, String plain_text) throws Exception {
		PrivateKey privateKey = convertPrivateKey(privateKeyStr);
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(plain_text.getBytes());
		byte[] outputDigest_sign = messageDigest.digest();
		//System.out.println("SHA-256加密后-----》" +bytesToHexString(outputDigest_sign));
		Signature Sign = Signature.getInstance("SHA256withRSA");
		Sign.initSign(privateKey);
		Sign.update(outputDigest_sign);
		//System.out.println("SHA256withRSA签名后-----》" + bytesToHexString(signed));
		return new String(Base64Util.base64Encode(Sign.sign()),"UTF-8");
	}
	
	/**
	 * 签名(明文SHA-256计算摘要，然后对摘要进行签名，签名算法：SHA256withRSA)
	 * 
	 * @param privateKey    私钥
	 * @param plain_text	明文
	 * @return	Base64编码签名之后的数据
	 * @throws Exception 
	 */
	public static String signBySHA256withRSA(PrivateKey privateKey, String plain_text) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(plain_text.getBytes());
		byte[] outputDigest_sign = messageDigest.digest();
		//System.out.println("SHA-256加密后-----》" +bytesToHexString(outputDigest_sign));
		Signature Sign = Signature.getInstance("SHA256withRSA");
		Sign.initSign(privateKey);
		Sign.update(outputDigest_sign);
		//System.out.println("SHA256withRSA签名后-----》" + bytesToHexString(signed));
		return new String(Base64Util.base64Encode(Sign.sign()),"UTF-8");
	}
	
	/**
	  * 验证数字签名
	  *
	  * @param keyInByte
	  *            打包成byte[]形式的公钥
	  * @param source
	  *            原文的数字摘要
	  * @param sign
	  *            签名（对原文的数字摘要的签名）
	  * @return 是否证实 boolean
	  */
	public static boolean verify(byte[] keyInByte, byte[] source, byte[] sign) throws Exception {
		KeyFactory mykeyFactory = KeyFactory.getInstance("RSA");
		Signature sig = Signature.getInstance("SHA256withRSA");
		X509EncodedKeySpec pub_spec = new X509EncodedKeySpec(keyInByte);
		PublicKey pubKey = mykeyFactory.generatePublic(pub_spec);
		sig.initVerify(pubKey);
		sig.update(source);
		return sig.verify(sign);
	}
	/**
	 * 验签(明文SHA-256计算摘要，然后校验签名，签名算法：SHA256withRSA)
	 * 
	 * @param publicKey	公钥
	 * @param plain_text	明文
	 * @param signed	 签名
	 * @return  true/false
	 */
	public static boolean verifySignBySHA256withRSA(PublicKey publicKey, String plain_text, byte[] signed) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(plain_text.getBytes());
		byte[] outputDigest_verify = messageDigest.digest();
		//System.out.println("SHA-256加密后-----》" +bytesToHexString(outputDigest_verify));
		Signature verifySign = Signature.getInstance("SHA256withRSA");
		verifySign.initVerify(publicKey);
		verifySign.update(outputDigest_verify);
		boolean SignedSuccess = verifySign.verify(signed);
		//System.out.println("验证成功？---" + SignedSuccess);
		return SignedSuccess;
	}
	
    public static PrivateKey convertPrivateKey(String keyStr)throws Exception{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64Util.base64Decode(keyStr.getBytes("UTF-8")));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
