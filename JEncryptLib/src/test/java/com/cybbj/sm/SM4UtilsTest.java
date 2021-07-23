package com.cybbj.sm;

import org.junit.Test;

import com.cybbj.util.Converts;

public class SM4UtilsTest {

	@Test
	public void testEncryptData_ECB() {
		try {
			System.out.println("sm4 算法验证 ");
			//System.out.println("明文: " + plainText);
			String plainText = "06123456FFFFFFFFFFFFFE9CAA9BFD6836983456FFFFFFFFFFFFFE9CAA9BAC23";
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
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
