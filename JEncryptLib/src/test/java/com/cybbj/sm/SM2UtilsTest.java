package com.cybbj.sm;

import org.junit.Test;

public class SM2UtilsTest {

	@Test
	public void test() throws Exception {
		//生成密钥对
//		SM2Utils.generateKeyPair();
		System.out.println("sm2算法验证");
		String plainText = "encryption standard111";
		System.out.println("明文:"+plainText);
		byte[] sourceData = plainText.getBytes();
//		
		String prik = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
		String pubk ="04435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
//				 
//		
		System.out.println("国密规范公钥16进制明文:"+pubk);
		System.out.println("国密规范私钥16进制明文:"+prik);
		/**********************  加解密    *************************/
		System.out.println("公钥加密: ");
		String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
		//cipherText="EHY7Z+gDnFZYUWrvBxnLF19Hw6RJz6/QCix7gIfMK9WXJ3gpCTMwWdzvKiWH1exH7coYzQYcA85ZIgqPV4CLdQt3OCxU1Ci2ecSGjj/FkpqxtXB4HfbrejSrBCoHGaREvMPe8YNbopXyvGqQXIk7BA==";
		System.out.println("原始密文:"+cipherText);
		plainText = Util.getHexString(SM2Utils.decryptBase64(Util.hexToByte(prik), cipherText));
		//plainText = Util.getHexString(SM2Utils.decryptString(Util.hexToByte(prik), "04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B89C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D650053A89B41C418B0C3AAD00D886C00286467"));
		System.out.println("私钥解密(HEX形式)2: "+plainText);
		System.out.println("私钥解密(明文形式)2: " +new String(SM2Utils.decryptBase64(Util.hexToByte(prik), cipherText)));
			
		/**********************  签名验签    *************************//*
		// 国密规范测试用户ID
		String userId = "ALICE123@YAHOO.COM";
		System.out.println("签名: ");
		byte[] c = SM2Utils.sign(userId.getBytes(), Util.hexToByte(prik), sourceData);
		System.out.println("sign: " + Util.getHexString(c));
		System.out.println("");
		
		System.out.println("验签: ");
		boolean vs = SM2Utils.verifySign(userId.getBytes(), Util.hexToByte(pubk), sourceData, c);
		System.out.println("验签结果: " + vs);
		System.out.println("");
		
		System.out.println(Util.getHexString(SecureUtil.base64Decode("TY+0z36l0zfDdgXpl/Lb2v1ZsKnDQgDpm14hOcKSLekWJXKkFSVfItAMHIVFzvBAPI4aCb2eUF3VyjWA0A1kKA==".getBytes())));
	*/
	}
}
