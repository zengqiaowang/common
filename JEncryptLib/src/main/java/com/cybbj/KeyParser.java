package com.cybbj;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.cybbj.contants.ErrorCode;

/**
 * 
 * KeyParser: 密钥转换类
 * 
 * @version 1.0
 * @author zengqiaowang
 * @modified 2014-4-16 v1.0 zengqiaowang 新建
 */
public class KeyParser {

	/**
	 * 
	 * convertPublicKey: 公钥转换 
	 *
	 * @param jkey 密钥key对象
	 * @return 转换后key对象
	 * @throws Exception 任何异常
	 */
	public static PublicKey convertPublicKey(JKeyParmater jkey)throws Exception {
		String keyType = jkey.getKeyType();
		if ((!(keyType.equals("RSA_Public")))
				&& (!(keyType.equals("DSA_Public")))
				&& (!(keyType.equals("ECIES_Public")))
				&& (!(keyType.equals("ECDSA_Public")))) {
			throw new Exception(ErrorCode.PUBKEYCONVFAIL + " : 公钥转换失败 密钥类型不合法 " + keyType);
		}
		PublicKey pubKey = null;
		try {
			String alg = keyType.substring(0, keyType.indexOf("_"));
			if (("ECIES".equals(alg)) || ("ECDSA".equals(alg))) {
				X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(jkey.getKey());
				KeyFactory f = KeyFactory.getInstance(alg, "BC");
				pubKey = f.generatePublic(pubSpec);
				return pubKey;
			}

			KeyFactory kf = KeyFactory.getInstance(alg, "BC");

			X509EncodedKeySpec x509spec = new X509EncodedKeySpec(jkey.getKey());
			pubKey = kf.generatePublic(x509spec);

			return pubKey;
		} catch (Exception ex) {
			throw new Exception(ErrorCode.PUBKEYCONVFAIL + " 公钥转换失败" + ex);
		}
	}

	/**
	 * 
	 * convertKey: 转换key方法 
	 *
	 * @param jkey 密钥key
	 * @return 转换后key对象
	 * @throws Exception 任何异常
	 */
	public static Key convertKey(JKeyParmater jkey) throws Exception {
		String keyType = jkey.getKeyType();

		if ((keyType.equals("DES")) || (keyType.equals("DESede"))
				|| (keyType.equals("RC2")) || (keyType.equals("RC4"))
				|| (keyType.equals("CAST5")) || (keyType.equals("IDEA"))
				|| (keyType.equals("AES"))
				|| (keyType.equals("PBEWithMD5AndDES"))
				|| (keyType.equals("PBEWITHSHAAND2-KEYTRIPLEDES-CBC"))
				|| (keyType.equals("PBEWITHSHAAND3-KEYTRIPLEDES-CBC")))
			return convertSecretKey(jkey);
		if ((keyType.equals("RSA_Private")) || (keyType.equals("DSA_Private"))
				|| (keyType.equals("ECIES_Private"))
				|| (keyType.equals("ECDSA_Private")))
			return convertPrivateKey(jkey);
		if ((keyType.equals("RSA_Public")) || (keyType.equals("DSA_Public"))
				|| (keyType.equals("ECIES_Public"))
				|| (keyType.equals("ECDSA_Public")))
			return convertPublicKey(jkey);

		throw new Exception(ErrorCode.KEYCONVFAIL + " : 密钥转换操作失败 密钥类型不合法 " + keyType);
	}

	/**
	 * 
	 * convertSecretKey: 转换对称密钥
	 *
	 * @param jkey 密钥key
	 * @return  转换后key
	 * @throws Exception 任何异常 
	 */
	public static SecretKey convertSecretKey(JKeyParmater jkey)throws Exception {
		SecretKey secretKey = null;
		try {
			if ((jkey.getKeyType().equals("PBEWithMD5AndDES"))
					|| (jkey.getKeyType()
							.equals("PBEWITHSHAAND2-KEYTRIPLEDES-CBC"))
					|| (jkey.getKeyType()
							.equals("PBEWITHSHAAND3-KEYTRIPLEDES-CBC"))) {
				char[] pwd = new String(jkey.getKey()).toCharArray();

				PBEKeySpec pbks = new PBEKeySpec(pwd);
				SecretKeyFactory kf = SecretKeyFactory.getInstance(jkey.getKeyType(), "BC");
				secretKey = kf.generateSecret(pbks);
				return secretKey;
			}
			secretKey = new SecretKeySpec(jkey.getKey(), jkey.getKeyType());
			return secretKey;
		} catch (Exception ex) {
			throw new Exception(ErrorCode.DCKEYCONVFAIL + " 对称密钥转换失败" + ex);
		}
	}

	/**
	 * 
	 * convertPrivateKey: 转换私钥key对象
	 *
	 * @param jkey 私钥key对象
	 * @return 转换后私钥key对象
	 * @throws Exception 任意异常
	 */
	public static PrivateKey convertPrivateKey(JKeyParmater jkey)throws Exception {
		String keyType = jkey.getKeyType();
		if ((!(keyType.equals("RSA_Private")))
				&& (!(keyType.equals("DSA_Private")))
				&& (!(keyType.equals("ECIES_Private")))
				&& (!(keyType.equals("ECDSA_Private")))) {
			throw new Exception(ErrorCode.PRIKEYCONVFAIL + ":私钥转换失败 密钥类型不合法 " + keyType);
		}
		PrivateKey prvKey = null;
		try {
			String alg = keyType.substring(0, keyType.indexOf("_"));
			if (("ECIES".equals(alg)) || ("ECDSA".equals(alg))) {

				PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(jkey.getKey());

				KeyFactory f = KeyFactory.getInstance(alg, "BC");
				PrivateKey privKey = f.generatePrivate(privSpec);

				return privKey;
			}

			KeyFactory kf = KeyFactory.getInstance(alg, "BC");

			PKCS8EncodedKeySpec p8KeySpec = new PKCS8EncodedKeySpec(jkey.getKey());
			prvKey = kf.generatePrivate(p8KeySpec);

			return prvKey;
		} catch (Exception ex) {
			throw new Exception(ErrorCode.PRIKEYCONVFAIL + " : 私钥转换失败", ex);
		}
	}
	
	/**
	 * 
	 * isEqualArray: 判断byte数组是否相等
	 *
	 * @param a byte数组a
	 * @param b byte数组b
	 * @return true||false
	 */
	public static boolean isEqualArray(byte[] a, byte[] b) {
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
