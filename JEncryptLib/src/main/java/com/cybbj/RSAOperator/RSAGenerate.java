package com.cybbj.RSAOperator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.cybbj.JKeyParmater;
import com.cybbj.JRSAKey;
import com.cybbj.Mechanism;
import com.cybbj.keyOperator.KeyGenerate;

/**
 * 
 * @author administrator
 * 
 *         非对称密钥操作类
 * 
 */
public class RSAGenerate extends KeyGenerate{

	/**
	 * 根据规则随机生成指定长度的RSA密钥对
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param keyLength
	 *            长度
	 * @return
	 * @throws Exception
	 */
	public JRSAKey generateKeyPair(int keyLength)throws Exception {
		Mechanism mechanism = new Mechanism("RSA");
		String mType = mechanism.getMechanismType();
		if (!(mechanism.isGenerateKeyPairabled())) {
			throw new Exception("8111 : 产生非对称密钥对失败 本操作不支持此种机制类型 " + mType);
		}

		KeyPair keyPair = null;
		PublicKey pubKey = null;
		PrivateKey prvKey = null;
		JKeyParmater jPubKey = null;
		JKeyParmater jPrvKey = null;
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(mType,
					"BC");
			keyPairGen.initialize(keyLength, new SecureRandom());
			keyPair = keyPairGen.generateKeyPair();

			pubKey = keyPair.getPublic();
			prvKey = keyPair.getPrivate();
			byte[] pubKeyEncoded = pubKey.getEncoded();
			byte[] prvKeyEncoded = prvKey.getEncoded();
			if (mechanism.getMechanismType().equals("RSA")) {
				jPubKey = new JKeyParmater("RSA_Public", pubKeyEncoded);
				jPrvKey = new JKeyParmater("RSA_Private", prvKeyEncoded);
			} else if (mechanism.getMechanismType().equals("DSA")) {
				jPubKey = new JKeyParmater("DSA_Public", pubKeyEncoded);
				jPrvKey = new JKeyParmater("DSA_Private", prvKeyEncoded);
			} else if (mechanism.getMechanismType().equals("ECDSA")) {
				jPubKey = new JKeyParmater("ECDSA_Public", pubKeyEncoded);
				jPrvKey = new JKeyParmater("ECDSA_Private", prvKeyEncoded);
			} else if (mechanism.getMechanismType().equals("ECIES")) {
				jPubKey = new JKeyParmater("ECIES_Public", pubKeyEncoded);
				jPrvKey = new JKeyParmater("ECIES_Private", prvKeyEncoded);
			}

			return new JRSAKey(jPubKey, jPrvKey);
		} catch (Exception ex) {
			throw new Exception("8111 : 产生非对称密钥对失败" + ex);
		}
	}
	
	
	/**
	 * RSA非对称密钥解密
	 * @param enKey
	 * 				密钥
	 * @param sourceData
	 * 				数据
	 * @return
	 * @throws Exception
	 */
	public byte[] decrypt(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("RSA/ECB/PKCS1PADDING");
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		return decryptData;
	}
	
	/**
	 * RSA非对称密钥加密
	 * @param enKey
	 * 				密钥
	 * @param sourceData
	 * 				数据	
	 * @return
	 * @throws Exception
	 */
	public byte[] encrypt(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("RSA/ECB/PKCS1PADDING");
		byte[] encryptData = super.encrypt(mechanism,enKey, sourceData);
		return encryptData;
	}
	
	/**
	 * RSA非对称密钥加密
	 * @param enKey
	 * 				私钥
	 * @param sourceData
	 * 				数据	
	 * @return
	 * @throws Exception
	 */
	public byte[] encrypt1(byte[] key , byte[] sourceData) throws Exception{
		JKeyParmater encKey = new JKeyParmater("RSA_Public",key);
		Mechanism mechanism = new Mechanism("RSA/ECB/PKCS1PADDING");
		byte[] encryptData = super.encrypt(mechanism,encKey, sourceData);
		return encryptData;
	}
	
	/**
	 * RSA非对称密钥解密
	 * @param enKey
	 * 				公钥
	 * @param sourceData
	 * 				数据
	 * @return
	 * @throws Exception
	 */
	public byte[] decrypt2(byte[] key , byte[] sourceData) throws Exception{
		JKeyParmater decKey = new JKeyParmater("RSA_Private",key);
		Mechanism mechanism = new Mechanism("RSA/ECB/PKCS1PADDING");
		byte[] decryptData = super.decrypt(mechanism, decKey, sourceData);
		return decryptData;
	}
	
	/**
	 * 处理加密机生成的密钥数据
	 * @param key
	 * 			密钥
	 * @param length
	 * 			长度
	 * @return
	 */
	public byte[] getRSAKey(byte[] key ,int length){
		
		if(key.length - length / 8 == 1){
			byte[] rsa_key = new byte[length];
			System.arraycopy(key, 1, rsa_key, 0, length);
			return rsa_key;
		} else if(key.length - length / 8 == 0){
			return key;
		} else {
			return null;
		}
		
	}


	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
