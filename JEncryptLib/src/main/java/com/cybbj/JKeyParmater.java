package com.cybbj;


/**
 * 
 * @author administrator
 * 
 * 密钥算法参数
 *
 */
public class JKeyParmater {
	
	/**
	 * SCB2
	 */
	public static final String SCB2_KEY = "SCB2";
	/**
	 * DES
	 */
	public static final String DES_KEY = "DES";
	/**
	 * DESede
	 */
	public static final String DES3_KEY = "DESede";
	/**
	 * RC2
	 */
	public static final String RC2_KEY = "RC2";
	/**
	 * RC4
	 */
	public static final String RC4_KEY = "RC4";
	/**
	 * CAST5
	 */
	public static final String CAST5_KEY = "CAST5";
	/**
	 * IDEA
	 */
	public static final String IDEA_KEY = "IDEA";
	/**
	 * AES
	 */
	public static final String AES_KEY = "AES";
	/**
	 * PBEWithMD5AndDES
	 */
	public static final String PBE_KEY = "PBEWithMD5AndDES";
	/**
	 * PBEWITHSHAAND2-KEYTRIPLEDES-CBC
	 */
	public static final String PBE_2KEY = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";
	/**
	 * PBEWITHSHAAND3-KEYTRIPLEDES-CBC
	 */
	public static final String PBE_3KEY = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
	/**
	 * SYMMETRY
	 */
	public static final String SYMMETRY_KEY = "SYMMETRY";
	/**
	 * MASTERKEY
	 */
	public static final String MASTER_KEY = "MASTERKEY";
	/**
	 * RSA_Private
	 */
	public static final String RSA_PRV_KEY = "RSA_Private";
	/**
	 * RSA_PrivateID
	 */
	public static final String RSA_PRV_KEY_ID = "RSA_PrivateID";
	/**
	 * RSA_Public
	 */
	public static final String RSA_PUB_KEY = "RSA_Public";
	/**
	 * RSA_PublicID
	 */
	public static final String RSA_PUB_KEY_ID = "RSA_PublicID";
	/**
	 * DSA_Private
	 */
	public static final String DSA_PRV_KEY = "DSA_Private";
	/**
	 * DSA_PrivateID
	 */
	public static final String DSA_PRV_KEY_ID = "DSA_PrivateID";
	/**
	 * DSA_Public
	 */
	public static final String DSA_PUB_KEY = "DSA_Public";
	/**
	 * DSA_PublicID
	 */
	public static final String DSA_PUB_KEY_ID = "DSA_PublicID";
	/**
	 * ECIES_Private
	 */
	public static final String ECIES_PRV_KEY = "ECIES_Private";
	/**
	 * EC_PrivateID
	 */
	public static final String ECIES_PRV_KEY_ID = "EC_PrivateID";
	/**
	 * ECIES_Public
	 */
	public static final String ECIES_PUB_KEY = "ECIES_Public";
	/**
	 * EC_PublicID
	 */
	public static final String ECIES_PUB_KEY_ID = "EC_PublicID";
	/**
	 * ECDSA_Private
	 */
	public static final String ECDSA_PRV_KEY = "ECDSA_Private";
	/**
	 * ECDSA_PrivateID
	 */
	public static final String ECDSA_PRV_KEY_ID = "ECDSA_PrivateID";
	/**
	 * ECDSA_Public
	 */
	public static final String ECDSA_PUB_KEY = "ECDSA_Public";
	/**
	 * ECDSA_PublicID
	 */
	public static final String ECDSA_PUB_KEY_ID = "ECDSA_PublicID";
	/**
	 * keyType
	 */
	private String keyType;
	/**
	 * key
	 */
	private byte[] key;
	/**
	 * keyID
	 */
	private long keyID;

	/**
	 * 
	* 构造方法
	* @param keyType 
	* @param key
	 */
	public JKeyParmater(String keyType, byte[] key) {
		this.keyType = keyType;
		this.key = key;
		this.keyID = -1L;
	}

	/**
	 * 
	 * 默认构造方法
	 */
	public JKeyParmater() {
	}

	/**
	 * 
	* 构造方法
	* @param keyType
	* @param keyID
	 */
	public JKeyParmater(String keyType, long keyID) {
		this.keyType = keyType;
		this.keyID = keyID;
		this.key = null;
	}

	/**
	 * 
	 * getKey: 获取key
	 *
	 * @return key值 
	 * @throws
	 */
	public byte[] getKey() {
		return this.key;
	}

	/**
	 * 
	 * getKeyID: 获取keyID
	 *
	 * @return keyID值 
	 * @throws
	 */
	public long getKeyID() {
		return this.keyID;
	}

	/**
	 * 
	 * getKeyType: 获取 keyType
	 *
	 * @return keyType值
	 * @throws
	 */
	public String getKeyType() {
		return this.keyType;
	}

	/**
	 * 
	 * setKeyType: 设置keyType
	 *
	 * @param keyType keyType
	 * @throws
	 */
	public void setKeyType(String keyType) {
		this.keyType = keyType;
	}
	
	/**
	 * 
	 * setKey: 设置key
	 *
	 * @param key key参数 
	 * @return key值
	 * @throws
	 */
	public void setKey(byte[] key) {
		this.key = key;
	}

	/**
	 * 
	 * setKeyID: 设置keyID 
	 *
	 * @param keyID keyID
	 * @throws
	 */
	public void setKeyID(long keyID) {
		this.keyID = keyID;
	}

}
