/**   
 * 类名：DESGenerateTest
 *
 */
package com.cybbj.desoperator;

import java.io.UnsupportedEncodingException;
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
		
/*		String src = "123";
		String secretKeyStr = "C4CA4238A0B92382";
		
		sourceEncryptData = src.getBytes();
		secretKey = secretKeyStr.getBytes();
		desGenerate = new DESGenerate();*/
		String src = "中文测试opabadafdsaf";
		String secretKeyStr = "D66B20E010DC382CD50B015B32ABC8CB";
		
		//sourceEncryptData = Converts.HexString2Bytes(src);
		try {
			sourceEncryptData = src.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		secretKey = Converts.HexString2Bytes(secretKeyStr);
		desGenerate = new DESGenerate();
	}

	/*@Test
	public void test3DES_CBC_16_PKCS() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			//enData = desGenerate.encryptByPKCS(key, sourceEncryptData);
			//deData = desGenerate.decryptByPKCS(key, enData);
			enData = Converts.HexString2Bytes("8DDFE8ABD46516AB4B3229CB3FAC8501");
			deData = desGenerate.decryptByPKCS(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("解密后数据:" + Converts.bytesToHexString(deData));
		//Assert.assertArrayEquals(sourceEncryptData, deData);
	}*/
	
/*	@Test
	public void test3DES_CBC_16_PBOC() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByCBCNOPADDING(key, sourceEncryptData);
			deData = desGenerate.decryptByCBCNOPADDING(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("CBC加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("CBC解密后数据:" + Converts.bytesToHexString(deData));
		//Assert.assertArrayEquals(sourceEncryptData, deData);
	}*/
	
		@Test
	public void test3DES_CBC_16_PBOC() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByCBCPKCS7Padding(key, sourceEncryptData);
			deData = desGenerate.decryptByCBCPKCS7Padding(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("CBC加密后数据:" + Converts.bytesToHexString(enData));
		//System.out.println("CBC解密后数据:" + Converts.bytesToHexString(deData));
		try {
			System.out.println("CBC解密后数据:" + new String(deData,"UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//Assert.assertArrayEquals(sourceEncryptData, deData);
	}
	
/*	@Test
	public void test3DES_ECB_16_PKCS() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			//enData = desGenerate.encryptByPKCS(key, sourceEncryptData);
			//deData = desGenerate.decryptByPKCS(key, enData);
			enData = Converts.HexString2Bytes("16EA394CC0B0861BF32409065253CD21");
			deData = desGenerate.decryptByPKCS(key, enData);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("解密后数据:" + Converts.bytesToHexString(deData));
		Assert.assertArrayEquals(sourceEncryptData, deData);
	}*/
/*	
	@Test
	public void testEncryptByECBNOPADDING() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByECBNOPADDING(key, sourceEncryptData);
			deData = desGenerate.decryptByECBNOPADDING(key, enData);			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("ECB加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("ECB解密后数据:" + Converts.bytesToHexString(deData));
		Assert.assertArrayEquals(sourceEncryptData, deData);
	}*/
	
	@Test
	public void testEncryptByECBPKCS7Padding() {
		Mechanism keyGen = new Mechanism("DESede");
		JKeyParmater key = new JKeyParmater(keyGen.getMechanismType(), secretKey);
		System.out.println("密钥类型：" + (key.getKeyType()));
		System.out.println("密钥数据：" + (Converts.bytesToHexString(key.getKey())));
		byte[] enData = null;
		byte[] deData = null;
		try {
			enData = desGenerate.encryptByECBPKCS7Padding(key, sourceEncryptData);
			deData = desGenerate.decryptByECBPKCS7Padding(key, enData);			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("ECB加密后数据:" + Converts.bytesToHexString(enData));
		System.out.println("ECB解密后数据:" + Converts.bytesToHexString(deData));
		Assert.assertArrayEquals(sourceEncryptData, deData);
	}

	@After
	public void destroyData() {
		sourceEncryptData = null;
	}
}
