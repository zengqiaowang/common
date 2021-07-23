package com.cybbj.sm;

import org.junit.Test;

import com.cybbj.util.Converts;

public class SM4UtilsUnionTest {
	@Test
	public void testSm4CbcEncrypt() {
		String hexKey = "F41F57C3E54413309ECFA8439D2FBA49";
		String hexData = "06123456FFFFFFFFFFFFFE9CAA9BFD6836983456FFFFFFFFFFFFFE9CAA9BAC23";
		byte[] encryptedBt = SM4UtilsUnion.sm4CbcEncrypt(Converts.HexString2Bytes(hexKey), Converts.HexString2Bytes(hexData), "PKCS7Padding");
		System.out.println(Converts.bytesToHexString(encryptedBt));
		byte[] decryptedBt = SM4UtilsUnion.sm4CbcDecrypt(Converts.HexString2Bytes(hexKey),encryptedBt, "PKCS7Padding");
		System.out.println(Converts.bytesToHexString(decryptedBt));
	}
	
	@Test
	public void testSm4EcbEncrypt() {
		String hexKey = "F41F57C3E54413309ECFA8439D2FBA49";
		String hexData = "06123456FFFFFFFFFFFFFE9CAA9BFD6879123456FFFFFFFFFFFFFE9CAA9BFD86";
		byte[] encryptedBt = SM4UtilsUnion.sm4EcbEncrypt(Converts.HexString2Bytes(hexKey), Converts.HexString2Bytes(hexData), "NoPadding");
		System.out.println(Converts.bytesToHexString(encryptedBt));
		byte[] decryptedBt = SM4UtilsUnion.sm4EcbDecrypt(Converts.HexString2Bytes(hexKey),encryptedBt, "NoPadding");
		System.out.println(Converts.bytesToHexString(decryptedBt));
	}
}
