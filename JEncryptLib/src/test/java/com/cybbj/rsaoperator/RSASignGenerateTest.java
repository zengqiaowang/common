package com.cybbj.rsaoperator;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Test;

import com.cybbj.RSAOperator.ParsePriKey;
import com.cybbj.RSAOperator.ParsePubKey;
import com.cybbj.RSAOperator.RSASignGenerate;
import com.cybbj.base64.Base64Util;

public class RSASignGenerateTest {
	
	@Test
	public void testSignBySHA256withRSA() {
		try {
			PrivateKey privateKey = ParsePriKey.getRsaPKCS1PrivateKey("RSA-server-key.pem", "F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
			String signedStr = RSASignGenerate.signBySHA256withRSA(privateKey, "abc");
			System.out.println(signedStr);
			X509Certificate x509Certificate = ParsePubKey.getCertFromFile("RSA-server-public.cer", "F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
			boolean verifyRes = RSASignGenerate.verifySignBySHA256withRSA(x509Certificate.getPublicKey(), "abc", Base64Util.base64Decode(signedStr.getBytes("UTF-8")));
			System.out.println(verifyRes);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
