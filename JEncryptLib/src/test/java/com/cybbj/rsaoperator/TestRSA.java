package com.cybbj.rsaoperator;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.cybbj.JRSAKey;
import com.cybbj.Mechanism;
import com.cybbj.RSAOperator.RSAGenerate;
import com.cybbj.util.Converts;

public class TestRSA {
	
	static {
		try {
			Security.addProvider(new BouncyCastleProvider());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static final byte[] src = "广西金融社保卡密钥加载服务1123".getBytes();

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			testCipher_RSA1024(src);
//			testHSM_RSA1024(src);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void testCipher_RSA1024(byte[] src) throws Exception {
		RSAGenerate rsaGenerate = new RSAGenerate();

		JRSAKey keyPair = rsaGenerate.generateKeyPair(1024);

		System.out.println("公钥：" + Converts.bytesToHexString(keyPair.getPublicKey().getKey()));
		System.out.println("私钥：" + Converts.bytesToHexString(keyPair.getPrivateKey().getKey()));

		Mechanism m2 = new Mechanism("RSA/ECB/PKCS1PADDING");

		byte[] enData = rsaGenerate.encrypt(m2, keyPair.getPublicKey(), src);
		
		byte[] deData = rsaGenerate.decrypt(m2, keyPair.getPrivateKey(), enData);

		System.out.println((isEqualArray(src, deData)));
		System.out.println(new String(deData));
	}
	
	private static boolean isEqualArray(byte[] a, byte[] b) {
		if (a.length != b.length) {
			return false;
		}

		for (int i = 0; i < a.length; ++i) {
			if (a[i] != b[i])
				return false;

		}

		return true;
	}

}
