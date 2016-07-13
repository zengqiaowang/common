/**   
 * 类名：DESGenerateTest
 *
 */
package com.cybbj.desoperator;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.cybbj.JKeyParmater;
import com.cybbj.Mechanism;
import com.cybbj.util.Converts;

/**
 * DESGenerateTest: 3DES测试类
 * 
 * @version 1.0
 * @author 15989
 * @modified 2016-7-13 v1.0 15989 新建
 */
public class DESGenerateTest {
	static {
		try {
			Security.addProvider(new BouncyCastleProvider());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	byte[] sourceEncryptData = null;
	byte[] secretKey = null;
	DESGenerate desGenerate = null;

	@Before
	public void initData() {
		
		String src = "123";
		String secretKeyStr = "C4CA4238A0B92382";
		
		sourceEncryptData = src.getBytes();
		secretKey = secretKeyStr.getBytes();
		desGenerate = new DESGenerate();
	}

	@Test
	public void test3DES_CBC_16_PKCS() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByPKCS(key, sourceEncryptData);
			deData = desGenerate.decryptByPKCS(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("解密后数据:" + Converts.bytesToHexString(deData));
		Assert.assertArrayEquals(sourceEncryptData, deData);
	}
	
	@Test
	public void test3DES_CBC_16_PBOC() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByPBOC(key, sourceEncryptData);
			deData = desGenerate.decryptByPBOC(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("解密后数据:" + Converts.bytesToHexString(deData));
		Assert.assertArrayEquals(sourceEncryptData, deData);
	}
	
	@Test
	public void test3DES_ECB_16_PKCS() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByPKCS(key, sourceEncryptData);
			deData = desGenerate.decryptByPKCS(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("解密后数据:" + Converts.bytesToHexString(deData));
		Assert.assertArrayEquals(sourceEncryptData, deData);
	}

	@After
	public void destroyData() {
		sourceEncryptData = null;
	}
}
