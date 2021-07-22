package com.cybbj.sm;

import org.junit.Test;

public class SM4UtilsTest {

	@Test
	public void testEncryptData_ECB() {
		try {
			/********************************** ECB模式start ***********************************/
			/*String plainText = "1234111111111111";
			SM4Utils sm4 = new SM4Utils();
			String key= "0123456789ABCDEFFEDCBA9876543210";
			sm4.secretKey = key;
			sm4.hexString = true;
			System.out.println("ECB模式");
			String cipherText = sm4.encryptData_ECB(plainText);
			System.out.println("密文: " + cipherText);
			System.out.println("");
			plainText = sm4.decryptData_ECB(cipherText);
			System.out.println("解密后明文：" + plainText);*/
			/********************************** ECB模式 end ***********************************/
			/********************************** CBC模式start ***********************************/
			String plainText = "1234111111111111";
			SM4Utils sm4 = new SM4Utils();
			String key= "0123456789ABCDEFFEDCBA9876543210";
			sm4.secretKey = key;
			sm4.hexString = true;
			sm4.iv = "00000000000000000000000000000000";
			System.out.println("CBC模式");
			String cipherText = sm4.encryptData_CBC(plainText);
			System.out.println("密文: " + cipherText);
			System.out.println("");
			plainText = sm4.decryptData_CBC(cipherText);
			System.out.println("解密后明文：" + plainText);
			/********************************** CBC模式 end ***********************************/
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
