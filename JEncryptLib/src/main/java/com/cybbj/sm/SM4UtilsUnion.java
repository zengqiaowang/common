package com.cybbj.sm;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * SM4 对称、分组加密：置换替换
 * 必须使用 bcprov-jdk15on包，而不能使用bcprov-jdk15包
 */
public class SM4UtilsUnion {

	/**
	 * SM4 Cbc模式 加密
	 * @param key 密钥
	 * @param data 明文
	 * @param padMode 填充模式
	 * @return 密文
	 */
	public static byte[] sm4CbcEncrypt(byte[] key, byte[] data, String padMode){
		byte[] res = null;
		String algorithm = "SM4/CBC/" + padMode;
		try {
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance(algorithm,"BC");  		
			SecretKeySpec secretKeySpec = getSm4Key(key);
			IvParameterSpec ivParameterSpec = getIv(cipher.getBlockSize());
			//byte[] padData = padding(data, cipher.getBlockSize());改为pkcs7填充 由bc来完成
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
	        res = cipher.doFinal(data); 
	        return res;  
		} catch (Exception e) {
			System.out.println("Fail: Sm4 Cbc Encrypt"+e);
		}
		return res;
	}
	
	/**
	 * SM4 Cbc模式 解密
	 * @param key 密钥
	 * @param data 密文
	 * @param padMode 填充模式
	 * @return 明文
	 */
	public static byte[] sm4CbcDecrypt(byte[] key, byte[] data, String padMode){
		byte[] res = null;
		String algorithm = "SM4/CBC/" + padMode;
		try {
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance(algorithm,"BC");
			SecretKeySpec secretKeySpec = getSm4Key(key);
			IvParameterSpec ivParameterSpec = getIv(cipher.getBlockSize());
			//byte[] padData = padding(data, cipher.getBlockSize()); 改为pkcs7填充 由bc来完成
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			res = cipher.doFinal(data); 
			return res;
		} catch (Exception e) {
			System.out.println("Fail: Sm4 Cbc Decrypt"+e);
		}
		return res;
	}
	
	/**
	 * SM4 Ecb模式 加密
	 * @param key 密钥
	 * @param data 明文
	 * @param padMode 填充模式
	 * @return 密文
	 */
	public static byte[] sm4EcbEncrypt(byte[] key, byte[] data, String padMode){
		byte[] res = null;
		String algorithm = "SM4/ECB/" + padMode;
		try {
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance(algorithm);
			SecretKeySpec secretKeySpec = getSm4Key(key);
			byte[] padData = padding(data, cipher.getBlockSize());
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			res = cipher.doFinal(padData);
		} catch (Exception e) {
			System.out.println("Fail: Sm4 Ecb Encrypt"+e);
		} 
		return res;
	}
	
	/**
	 * SM4 Ecb模式 解密
	 * @param key 密钥
	 * @param data 密文
	 * @param padMode 填充模式
	 * @return 明文
	 */
	public static byte[] sm4EcbDecrypt(byte[] key, byte[] data, String padMode) {	
		byte[] res = null;
		String algorithm = "SM4/ECB/" + padMode;
		try {
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance(algorithm);
			SecretKeySpec secretKeySpec = getSm4Key(key);
//			byte[] padData = padding(data, cipher.getBlockSize());
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			res = cipher.doFinal(data);
		} catch (Exception e) {
			System.out.println("Fail: Sm4 Ecb Decrypt"+e);
		}
		return res;
	}

	/**
	 * 生成国密Key：SM4，密钥为 128bit， 16byte
	 */
	public static SecretKeySpec getSm4Key(byte[] key) {	
		if (key.length != 16) {
			System.out.println("SM4's key should be 16bytes, 128bits");
		}
		return new SecretKeySpec(key, "SM4");
	}
	
	/**
	 * 初始化向量
	 * @param len 长度
	 * @return
	 */
	public static IvParameterSpec getIv(int len) {
		//使用 IV 的例子是反馈模式中的密码，如，CBC 模式中的 DES 和使用 OAEP 编码操作的 RSA 密码
		byte[] zero = new byte[len];
		IvParameterSpec ivps = new IvParameterSpec(zero);
		return ivps;
	}

	/**
	 * 补足长度
	 * @param src
	 * @param len
	 * @return
	 */
	public static byte[] padding(byte[] src, int len) {
		int paddingLength = len - src.length % len;
		if (len == paddingLength) {
			return src;
		}
		byte[] newsrc = new byte[src.length + paddingLength];
		System.arraycopy(src, 0, newsrc, 0, src.length);
		for(int i = 0;i< paddingLength;i++)
		{
			newsrc[src.length+i] = (byte) 0xFF;
		}
		return newsrc;
	}

	
}
