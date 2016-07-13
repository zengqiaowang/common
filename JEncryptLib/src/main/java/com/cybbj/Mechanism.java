package com.cybbj;


/**
 * 
 * @author administrator
 * 
 * 密钥生成规则
 *
 */
public class Mechanism {

	/**
	 * RSA
	 */
	public static final String RSA = "RSA";
	/**
	 * RSA/ECB/PKCS1PADDING
	 */
	public static final String RSA_PKCS = "RSA/ECB/PKCS1PADDING";
	/**
	 * DSA
	 */
	public static final String DSA = "DSA";
	/**
	 * ECIES
	 */
	public static final String ECIES = "ECIES";
	/**
	 * ECDSA
	 */
	public static final String ECDSA = "ECDSA";
	/**
	 * DES
	 */
	public static final String DES_KEY = "DES";
	/**
	 * DES/ECB/PKCS7Padding
	 */
	public static final String DES_ECB = "DES/ECB/PKCS7Padding";
	/**
	 * DES/ECB/NOPADDING
	 */
	public static final String DES_ECB_NOPADDING = "DES/ECB/NOPADDING";
	/**
	 * DES/CBC/PKCS7Padding
	 */
	public static final String DES_CBC = "DES/CBC/PKCS7Padding";
	/**
	 * RC2
	 */
	public static final String RC2_KEY = "RC2";
	/**
	 * RC2/ECB/PKCS7Padding
	 */
	public static final String RC2_ECB = "RC2/ECB/PKCS7Padding";
	/**
	 * RC2/CBC/PKCS7Padding
	 */
	public static final String RC2_CBC = "RC2/CBC/PKCS7Padding";
	/**
	 * RC4
	 */
	public static final String RC4_KEY = "RC4";
	/**
	 * RC4
	 */
	public static final String RC4 = "RC4";
	/**
	 * DESede
	 */
	public static final String DES3_KEY = "DESede";
	/**
	 * DESede/ECB/PKCS7Padding
	 */
	public static final String DES3_ECB = "DESede/ECB/PKCS7Padding";
	/**
	 * DESede/CBC/PKCS7Padding
	 */
	public static final String DES3_CBC = "DESede/CBC/PKCS7Padding";
	/**
	 * CAST5
	 */
	public static final String CAST5_KEY = "CAST5";
	/**
	 * CAST5/ECB/PKCS7Padding
	 */
	public static final String CAST5_ECB = "CAST5/ECB/PKCS7Padding";
	/**
	 * CAST5/CBC/PKCS7Padding
	 */
	public static final String CAST5_CBC = "CAST5/CBC/PKCS7Padding";
	/**
	 * IDEA
	 */
	public static final String IDEA_KEY = "IDEA";
	/**
	 * IDEA/ECB/PKCS7Padding
	 */
	public static final String IDEA_ECB = "IDEA/ECB/PKCS7Padding";
	/**
	 * IDEA/CBC/PKCS7Padding
	 */
	public static final String IDEA_CBC = "IDEA/CBC/PKCS7Padding";
	/**
	 * AES
	 */
	public static final String AES_KEY = "AES";
	/**
	 * AES/ECB/PKCS7Padding
	 */
	public static final String AES_ECB = "AES/ECB/PKCS7Padding";
	/**
	 * AES/CBC/PKCS7Padding
	 */
	public static final String AES_CBC = "AES/CBC/PKCS7Padding";
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
	 * PBEWithMD5AndDES
	 */
	public static final String PBE_MD5_DES = "PBEWithMD5AndDES";
	/**
	 * PBEWithMD5AndRC2
	 */
	public static final String PBE_MD5_RC2 = "PBEWithMD5AndRC2";
	/**
	 * PBEWithSHA1AndDES
	 */
	public static final String PBE_SHA1_DES = "PBEWithSHA1AndDES";
	/**
	 * PBEWITHSHAAND2-KEYTRIPLEDES-CBC
	 */
	public static final String PBE_SHA1_2DES = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";
	/**
	 * PBEWITHSHAAND3-KEYTRIPLEDES-CBC
	 */
	public static final String PBE_SHA1_3DES = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
	/**
	 * PBEWithSHA1AndRC2
	 */
	public static final String PBE_SHA1_RC2 = "PBEWithSHA1AndRC2";
	/**
	 * SF33
	 */
	public static final String SF33_KEY = "SF33";
	/**
	 * SF33_ECB
	 */
	public static final String SF33_ECB = "SF33_ECB";
	/**
	 * SF33_CBC
	 */
	public static final String SF33_CBC = "SF33_CBC";
	/**
	 * SCB2
	 */
	public static final String SCB2_KEY = "SCB2";
	/**
	 * SCB2_ECB
	 */
	public static final String SCB2_ECB = "SCB2_ECB";
	/**
	 * SCB2_CBC
	 */
	public static final String SCB2_CBC = "SCB2_CBC";
	/**
	 * SYMMETRY
	 */
	public static final String SYMMETRY_KEY = "SYMMETRY";
	/**
	 * MASTERKEY
	 */
	public static final String MASTER_KEY = "MASTERKEY";
	/**
	 * MD2
	 */
	public static final String MD2 = "MD2";
	/**
	 * MD5
	 */
	public static final String MD5 = "MD5";
	/**
	 * SHA1
	 */
	public static final String SHA1 = "SHA1";
	/**
	 * SHA256
	 */
	public static final String SHA256 = "SHA256";
	/**
	 * SHA384
	 */
	public static final String SHA384 = "SHA384";
	/**
	 * SHA512
	 */
	public static final String SHA512 = "SHA512";
	/**
	 * SHA224
	 */
	public static final String SHA224 = "SHA224";
	/**
	 * MD2withRSAEncryption
	 */
	public static final String MD2_RSA = "MD2withRSAEncryption";
	/**
	 * MD5withRSAEncryption
	 */
	public static final String MD5_RSA = "MD5withRSAEncryption";
	/**
	 * SHA1withRSAEncryption
	 */
	public static final String SHA1_RSA = "SHA1withRSAEncryption";
	/**
	 * SHA1withDSA
	 */
	public static final String SHA1_DSA = "SHA1withDSA";
	/**
	 * SHA224withDSA
	 */
	public static final String SHA224_DSA = "SHA224withDSA";
	/**
	 * SHA256withDSA
	 */
	public static final String SHA256_DSA = "SHA256withDSA";
	/**
	 * SHA1withECDSA
	 */
	public static final String SHA1_EC_DSA = "SHA1withECDSA";
	/**
	 * SHA224withECDSA
	 */
	public static final String SHA224_EC_DSA = "SHA224withECDSA";
	/**
	 * SHA256withECDSA
	 */
	public static final String SHA256_EC_DSA = "SHA256withECDSA";
	/**
	 * SHA224withRSAEncryption
	 */
	public static final String SHA224_RSA = "SHA224withRSAEncryption";
	/**
	 * SHA256withRSAEncryption
	 */
	public static final String SHA256_RSA = "SHA256withRSAEncryption";
	/**
	 * SHA384withRSAEncryption
	 */
	public static final String SHA384_RSA = "SHA384withRSAEncryption";
	/**
	 * SHA512withRSAEncryption
	 */
	public static final String SHA512_RSA = "SHA512withRSAEncryption";
	/**
	 * HMac-MD2
	 */
	public static final String HMAC_MD2 = "HMac-MD2";
	/**
	 * HMac-MD5
	 */
	public static final String HMAC_MD5 = "HMac-MD5";
	/**
	 * HMac-SHA1
	 */
	public static final String HMAC_SHA1 = "HMac-SHA1";
	/**
	 * CKM_RSA_RAW
	 */
	public static final String RAW = "CKM_RSA_RAW";
	/**
	 * Random
	 */
	public static final String RANDOM = "Random";
	
	/**
	 * 机制原理类型
	 */
	private String mechanismType;
	
	/**
	 * 参数
	 */
	private Object param;

	/**
	 * 构造方法
	 *
	 * @param mechanismType 
	 * @param param
	 */
	public Mechanism(String mechanismType, Object param) {
		this.mechanismType = mechanismType;
		this.param = param;
	}

	/**
	 * 构造方法 
	 *
	 * @param mechanismType 加密原理类型
	 */
	public Mechanism(String mechanismType) {
		this.mechanismType = mechanismType;
		this.param = null;
	}

	/**
	 * 
	 * getMechanismType: 获取加密原理类型
	 *
	 * @return 加密原理类型 
	 * @throws
	 */
	public String getMechanismType() {
		return this.mechanismType;
	}

	/**
	 * 
	 * getParam: 获取参数
	 *
	 * @return 参数值
	 * @throws
	 */
	public Object getParam() {
		return this.param;
	}

	/**
	 * 
	 * setParam: 设置参数
	 *
	 * @param param 参数 
	 * @return 参数值
	 * @throws
	 */
	public void setParam(Object param) {
		this.param = param;
	}

	/**
	 * 
	 * setMechanismType: 设置加密原理类型
	 *
	 * @param mechanismType 加密原理类型
	 * @throws
	 */
	public void setMechanismType(String mechanismType) {
		this.mechanismType = mechanismType;
	}

	
	/**
	 * 
	 * isDigestabled: 判断加密原理类型是否为以下值：MD2,MD5,SHA1,SHA224,SHA256
	 * ,SHA384,SHA512
	 *
	 * @return true|false
	 * @throws
	 */
	public boolean isDigestabled() {
		boolean suport = false;
		if (("MD2".equals(this.mechanismType))
				|| ("MD5".equals(this.mechanismType))
				|| ("SHA1".equals(this.mechanismType))
				|| ("SHA224".equals(this.mechanismType))
				|| ("SHA256".equals(this.mechanismType))
				|| ("SHA384".equals(this.mechanismType))
				|| ("SHA512".equals(this.mechanismType)))
			suport = true;

		return suport;
	}

	/**
	 * 
	 * isSignabled: 判断加密原理类型是否为以下值：MD2withRSAEncryption,MD5withRSAEncryption
	 * ,SHA1withRSAEncryption,SHA1withDSA,SHA1withECDSA,SHA224withDSA,SHA256withDSA,
	 * SHA224withECDSA,SHA256withECDSA,SHA224withRSAEncryption,SHA256withRSAEncryption,
	 * SHA384withRSAEncryption,SHA512withRSAEncryption,RSA/ECB/PKCS1PADDING
	 *
	 * @return true|false
	 * @throws
	 */
	public boolean isSignabled() {
		boolean suport = false;
		if (("MD2withRSAEncryption".equals(this.mechanismType))
				|| ("MD5withRSAEncryption".equals(this.mechanismType))
				|| ("SHA1withRSAEncryption".equals(this.mechanismType))
				|| ("SHA1withDSA".equals(this.mechanismType))
				|| ("SHA1withECDSA".equals(this.mechanismType))
				|| ("SHA224withDSA".equals(this.mechanismType))
				|| ("SHA256withDSA".equals(this.mechanismType))
				|| ("SHA224withECDSA".equals(this.mechanismType))
				|| ("SHA256withECDSA".equals(this.mechanismType))
				|| ("SHA224withRSAEncryption".equals(this.mechanismType))
				|| ("SHA256withRSAEncryption".equals(this.mechanismType))
				|| ("SHA384withRSAEncryption".equals(this.mechanismType))
				|| ("SHA512withRSAEncryption".equals(this.mechanismType))
				|| ("RSA/ECB/PKCS1PADDING".equals(this.mechanismType))) {
			suport = true;
		}
		return suport;
	}

	/**
	 * 
	 * isSignabled: 判断加密原理类型是否为以下值：RSA,DSA,ECIES,ECDSA
	 *
	 * @return true|false
	 * @throws
	 */
	public boolean isGenerateKeyPairabled() {
		boolean suport = false;
		if (("RSA".equals(this.mechanismType))
				|| ("DSA".equals(this.mechanismType))
				|| ("ECIES".equals(this.mechanismType))
				|| ("ECDSA".equals(this.mechanismType)))
			suport = true;

		return suport;
	}
}
