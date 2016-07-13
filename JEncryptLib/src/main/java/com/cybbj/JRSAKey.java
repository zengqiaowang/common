package com.cybbj;

/**
 * 
 * @author administrator
 *
 * RSA 密钥参数
 *
 */
public class JRSAKey {
	
	/**
	 * 公钥key
	 */
	private JKeyParmater pubKey;
	/**
	 * 私钥key
	 */
	private JKeyParmater prvKey;

	/**
	 * 
	* 构造方法
	* @param pubKey 公钥
	* @param prvKey 私钥
	 */
	public JRSAKey(JKeyParmater pubKey, JKeyParmater prvKey) {
		this.pubKey = pubKey;
		this.prvKey = prvKey;
	}

	/**
	 * 
	 * getPublicKey: 获取公钥key
	 *
	 * @return 公钥key
	 * @throws
	 */
	public JKeyParmater getPublicKey() {
		return this.pubKey;
	}

	/**
	 * 
	 * getPrivateKey: 获取私钥key 
	 *
	 * @return 私钥key
	 * @throws
	 */
	public JKeyParmater getPrivateKey() {
		return this.prvKey;
	}
}
