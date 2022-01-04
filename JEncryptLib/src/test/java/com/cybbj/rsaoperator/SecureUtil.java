package com.cybbj.rsaoperator;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.bouncycastle.util.encoders.Base64;

/**
 * 
 * @author zengqiaowang
 * 加解密算法类
 *
 */
public class SecureUtil {
	
	/**
	 * 公钥加密数据
	 * @param publicKey
	 * @param plainData
	 * @return
	 * @throws Exception
	 */
	public static byte[] rsaEncryptedData(RSAPublicKey publicKey, byte[] plainData)
			throws Exception {
		try {
			//RSA/ECB/PKCS1Padding	RSA/ECB/NoPadding
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",
					new org.bouncycastle.jce.provider.BouncyCastleProvider());
			String algorithm = cipher.getAlgorithm();
			int rsaLen = publicKey.getModulus().bitLength();
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			int blockSize = cipher.getBlockSize();
			if ("RSA/ECB/NoPadding".equalsIgnoreCase(algorithm)) {
				blockSize = rsaLen/8;
			}
			int outputSize = cipher.getOutputSize(plainData.length);
			int leavedSize = plainData.length % blockSize;
			int blocksSize = leavedSize != 0 ? plainData.length / blockSize + 1
					: plainData.length / blockSize;
			byte[] raw = new byte[outputSize * blocksSize];
			int i = 0;
			while (plainData.length - i * blockSize > 0) {
				if (plainData.length - i * blockSize > blockSize) {
					cipher.doFinal(plainData, i * blockSize, blockSize, raw, i
							* outputSize);
				} else {
					cipher.doFinal(plainData, i * blockSize, plainData.length
							- i * blockSize, raw, i * outputSize);
				}
				i++;
			}
			return raw;
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * 
	 * @param privateKey
	 * @param cryptPin
	 * @return
	 * @throws Exception
	 */
	public static byte[] rsaDecryptedData(RSAPrivateKey privateKey, byte[] cryptPin)
			throws Exception {
		try {
			//RSA/ECB/PKCS1Padding	RSA/ECB/NoPadding
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",
					new org.bouncycastle.jce.provider.BouncyCastleProvider());
			String algorithm = cipher.getAlgorithm();
			int rsaLen = privateKey.getModulus().bitLength();
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			int blockSize = cipher.getBlockSize();
			if ("RSA/ECB/NoPadding".equalsIgnoreCase(algorithm)) {
				blockSize = rsaLen/8;
			}
			int outputSize = cipher.getOutputSize(cryptPin.length);
			int leavedSize = cryptPin.length % blockSize;
			int blocksSize = leavedSize != 0 ? cryptPin.length / blockSize + 1
					: cryptPin.length / blockSize;
			byte[] pinData = new byte[outputSize * blocksSize];
			int i = 0;
			while (cryptPin.length - i * blockSize > 0) {
				if (cryptPin.length - i * blockSize > blockSize) {
					cipher.doFinal(cryptPin, i * blockSize, blockSize, pinData,
							i * outputSize);
				} else {
					cipher.doFinal(cryptPin, i * blockSize, cryptPin.length - i
							* blockSize, pinData, i * outputSize);
				}
				i++;
			}
			return pinData;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	

	/**
	 * BASE64解码
	 * 
	 * @param inputByte
	 *            待解码数据
	 * @return 解码后的数据
	 * @throws IOException
	 */
	public static byte[] base64Decode(byte[] inputByte) throws IOException {
		return Base64.decode(inputByte);
	}

	/**
	 * BASE64编码
	 * 
	 * @param inputByte
	 *            待编码数据
	 * @return 解码后的数据
	 * @throws IOException
	 */
	public static byte[] base64Encode(byte[] inputByte) throws IOException {
		return Base64.encode(inputByte);
	}

}
