package com.cybbj.keyOperator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;

import com.cybbj.JKeyParmater;
import com.cybbj.KeyParser;
import com.cybbj.Mechanism;
import com.cybbj.param.CBCParam;
import com.cybbj.param.PBEParam;
import com.cybbj.util.Converts;

public class KeyGenerate {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

	// ******************************************************加解密文件流函数************************************************************************/
	/**
	 * 加密输入流
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param enKey
	 *            密钥
	 * @param sourceData
	 *            输入流
	 * @return
	 * @throws Exception
	 */
	public byte[] encrypt(Mechanism mechanism, JKeyParmater enKey,
			InputStream sourceData) throws Exception {
		try {
			return doCipher(mechanism, enKey, true, sourceData);
		} catch (Exception ex) {
			throw new Exception("8120 : 加密操作失败" + ex);
		}
	}

	/**
	 * 解密输入流
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param deKey
	 *            密钥
	 * @param encryptedData
	 *            输入流
	 * @return
	 * @throws Exception
	 */
	public byte[] decrypt(Mechanism mechanism, JKeyParmater deKey,
			InputStream encryptedData) throws Exception {
		try {
			return doCipher(mechanism, deKey, false, encryptedData);
		} catch (Exception ex) {
			throw new Exception("8121 : 解密操作失败" + ex);
		}
	}

	/**
	 * 
	 * encrypt: 加密方法
	 *
	 * @param mechanism  密钥生成规则
	 * @param enKey  密钥算法
	 * @param sourceData  输入流
	 * @param out   输出流
	 * @throws Exception 参数描述 
	 * @return 
	 * @throws
	 */
	public int encrypt(Mechanism mechanism, JKeyParmater enKey,
			InputStream sourceData, OutputStream out) throws Exception {
		int len = 0;
		try {
			len = doCipher(mechanism, enKey, true, sourceData, out);
		} catch (Exception ex) {
			throw new Exception("8120 : 加密操作失败", ex);
		}
		return len;
	}

	public int decrypt(Mechanism mechanism, JKeyParmater deKey,
			InputStream encryptedData, OutputStream out) throws Exception {
		byte[] dec;
		try {
			dec = doCipher(mechanism, deKey, false, encryptedData);
			out.write(dec);
		} catch (Exception ex) {
			throw new Exception("8121 : 解密操作失败", ex);
		}
		return dec.length;
	}

	/**
	 * 加密主方法
	 * @param mechanism 密钥规则
	 * @param jkey  密钥
	 * @param isEncrypt   是否加密
	 * @param data   需加密源流
	 */
	protected byte[] doCipher(Mechanism mechanism, JKeyParmater jkey,
			boolean isEncrypt, InputStream data) throws Exception {
		String mType = mechanism.getMechanismType();

		int rsaKeyLen = -1;
		if (mType.equalsIgnoreCase("RSA/ECB/PKCS1PADDING")) {
			if (jkey.getKeyType().equals("RSA_Public")) {
				RSAPublicKey pubKey = (RSAPublicKey) KeyParser
						.convertPublicKey(jkey);
				rsaKeyLen = pubKey.getModulus().bitLength();
			} else if (jkey.getKeyType().equals("RSA_Private")) {
				RSAPrivateKey prvKey = (RSAPrivateKey) KeyParser
						.convertPrivateKey(jkey);
				rsaKeyLen = prvKey.getModulus().bitLength();
			}

			if (rsaKeyLen > 2048) {
				byte[] bs = new byte[data.available()];
				data.read(bs);
				data.close();
				return doCipher_RSA_ext(mechanism, jkey, isEncrypt, bs);
			}

		}

		Cipher cipher = Cipher.getInstance(mType, "BC");
		int cipherMode = 0;
		if (isEncrypt)
			cipherMode = 1;
		else {
			cipherMode = 2;
		}

		if (mType.indexOf("CBC") != -1) {
			CBCParam cbcParam = (CBCParam) mechanism.getParam();
			if (cbcParam == null)
				throw new Exception("CBC参数为空");

			IvParameterSpec iv = new IvParameterSpec(cbcParam.getIv());
			cipher.init(cipherMode, KeyParser.convertKey(jkey), iv);
		} else if (mType.indexOf("PBE") != -1) {
			PBEParam pbeParam = (PBEParam) mechanism.getParam();
			if (pbeParam == null)
				throw new Exception("PBE参数为空");

			PBEParameterSpec pbeSpec = new PBEParameterSpec(pbeParam.getSalt(),
					pbeParam.getIterations());

			cipher.init(cipherMode, KeyParser.convertKey(jkey), pbeSpec);
		} else {
			cipher.init(cipherMode, KeyParser.convertKey(jkey));
		}

		ByteArrayOutputStream bin = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int i = 0;

		while ((i = data.read(buffer)) > 0) {
			byte[] temp = cipher.update(buffer, 0, i);
			bin.write(temp);
		}

		byte[] res = cipher.doFinal();
		bin.write(res);
		return bin.toByteArray();
	}

	protected int doCipher(Mechanism mechanism, JKeyParmater jkey,
			boolean isEncrypt, InputStream data, OutputStream out)
			throws Exception {
		String mType = mechanism.getMechanismType();

		int rsaKeyLen = -1;
		if (mType.equalsIgnoreCase("RSA/ECB/PKCS1PADDING")) {
			if (jkey.getKeyType().equals("RSA_Public")) {
				RSAPublicKey pubKey = (RSAPublicKey) KeyParser
						.convertPublicKey(jkey);
				rsaKeyLen = pubKey.getModulus().bitLength();
			} else if (jkey.getKeyType().equals("RSA_Private")) {
				RSAPrivateKey prvKey = (RSAPrivateKey) KeyParser
						.convertPrivateKey(jkey);
				rsaKeyLen = prvKey.getModulus().bitLength();
			}

			if (rsaKeyLen > 2048) {
				byte[] bs = new byte[data.available()];
				data.read(bs);
				data.close();
				byte[] temp = doCipher_RSA_ext(mechanism, jkey, isEncrypt, bs);
				out.write(temp);
				return temp.length;
			}

		}

		Cipher cipher = Cipher.getInstance(mType, "BC");
		int cipherMode = 0;
		if (isEncrypt)
			cipherMode = 1;
		else {
			cipherMode = 2;
		}

		if (mType.indexOf("CBC") != -1) {
			CBCParam cbcParam = (CBCParam) mechanism.getParam();
			if (cbcParam == null)
				throw new Exception("CBC参数为空");

			IvParameterSpec iv = new IvParameterSpec(cbcParam.getIv());
			cipher.init(cipherMode, KeyParser.convertKey(jkey), iv);
		} else if (mType.indexOf("PBE") != -1) {
			PBEParam pbeParam = (PBEParam) mechanism.getParam();
			if (pbeParam == null)
				throw new Exception("PBE参数为空");

			PBEParameterSpec pbeSpec = new PBEParameterSpec(pbeParam.getSalt(),
					pbeParam.getIterations());

			cipher.init(cipherMode, KeyParser.convertKey(jkey), pbeSpec);
		} else {
			cipher.init(cipherMode, KeyParser.convertKey(jkey));
		}

		byte[] buffer = new byte[1024];
		int i = 0;
		int datalen = 0;

		while ((i = data.read(buffer)) > 0) {
			byte[] aa = cipher.update(buffer, 0, i);
			out.write(aa);
			datalen += aa.length;
		}
		byte[] last = cipher.doFinal();
		out.write(last);
		datalen += last.length;
		return datalen;
	}

	// ******************************************************加解密文件流函数************************************************************************/

	// ******************************************************加解密数据流函数************************************************************************/
	/**
	 * 加密数据流
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param enKey
	 *            密钥
	 * @param sourceData
	 *            需处理的流
	 * @return
	 * @throws Exception
	 */
	public byte[] encrypt(Mechanism mechanism, JKeyParmater enKey,
			byte[] sourceData) throws Exception {
		try {
			return doCipher(mechanism, enKey, true, sourceData);
		} catch (Exception ex) {
			throw new Exception("8120:加密操作失败", ex);
		}
	}

	/**
	 * 解密数据流
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param deKey
	 *            密钥
	 * @param encryptedData
	 *            需处理的流
	 * @return
	 * @throws Exception
	 */
	public byte[] decrypt(Mechanism mechanism, JKeyParmater deKey,
			byte[] encryptedData) throws Exception {
		try {
			return doCipher(mechanism, deKey, false, encryptedData);
		} catch (Exception ex) {
			throw new Exception("8121:解密操作失败", ex);
		}
	}

	/**
	 * 数据加解密具体实现
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param jkey
	 *            密钥
	 * @param isEncrypt
	 * @param data
	 *            处理流
	 * @return
	 * @throws Exception
	 */
	protected byte[] doCipher(Mechanism mechanism, JKeyParmater jkey,
			boolean isEncrypt, byte[] data) throws Exception {
		String mType = mechanism.getMechanismType();

		int rsaKeyLen = -1;
		if (mType.equalsIgnoreCase("RSA/ECB/PKCS1PADDING")) {
			if (jkey.getKeyType().equals("RSA_Public")) {
				RSAPublicKey pubKey = (RSAPublicKey) KeyParser
						.convertPublicKey(jkey);
				rsaKeyLen = pubKey.getModulus().bitLength();
			} else if (jkey.getKeyType().equals("RSA_Private")) {
				RSAPrivateKey prvKey = (RSAPrivateKey) KeyParser
						.convertPrivateKey(jkey);
				rsaKeyLen = prvKey.getModulus().bitLength();
			}

			if (rsaKeyLen > 2048) {
				return doCipher_RSA_ext(mechanism, jkey, isEncrypt, data);
			}

		}

		Cipher cipher = Cipher.getInstance(mType, "BC");
		int cipherMode = 0;

		if (isEncrypt)
			cipherMode = 1;
		else {
			cipherMode = 2;
		}

		if (mType.indexOf("PBE") != -1) {
			PBEParam pbeParam = (PBEParam) mechanism.getParam();
			if (pbeParam == null)
				throw new Exception("PBE参数为空");

			PBEParameterSpec pbeSpec = new PBEParameterSpec(pbeParam.getSalt(),
					pbeParam.getIterations());

			cipher.init(cipherMode, KeyParser.convertKey(jkey), pbeSpec);
		} else if (mType.indexOf("CBC") != -1) {
			CBCParam cbcParam = (CBCParam) mechanism.getParam();
			if (cbcParam == null)
				throw new Exception("CBC参数为空");

			IvParameterSpec iv = new IvParameterSpec(cbcParam.getIv());
			cipher.init(cipherMode, KeyParser.convertKey(jkey), iv);
		}  else {
			cipher.init(cipherMode, KeyParser.convertKey(jkey));
		}

		byte[] res = null;
		
		if( mType.equalsIgnoreCase("DESede/ECB/NOPADDING")){
			 res = cipher.doFinal(set3DESDateNOPADDING(data));
		}else{
			res = cipher.doFinal(data);
		}
		return res;
	}

	/**
	 * 以私钥分量方式加解密数据流
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param jkey
	 *            密钥
	 * @param isEncrypt
	 * @param data
	 *            处理流
	 * @return
	 * @throws Exception
	 */
	protected byte[] doCipher_RSA_ext(Mechanism mechanism, JKeyParmater jkey,
			boolean isEncrypt, byte[] data) throws Exception {
		AsymmetricBlockCipher eng = new RSAEngine();
		RSAKeyParameters keyParams = null;
		if (jkey.getKeyType().equals("RSA_Public")) {
			JCERSAPublicKey pubKey = (JCERSAPublicKey) KeyParser
					.convertPublicKey(jkey);
			keyParams = new RSAKeyParameters(false, pubKey.getModulus(), pubKey
					.getPublicExponent());
		} else {
			JCERSAPrivateCrtKey prvKey = (JCERSAPrivateCrtKey) KeyParser
					.convertPrivateKey(jkey);
			keyParams = new RSAPrivateCrtKeyParameters(prvKey.getModulus(),
					prvKey.getPublicExponent(), prvKey.getPrivateExponent(),
					prvKey.getPrimeP(), prvKey.getPrimeQ(), prvKey
							.getPrimeExponentP(), prvKey.getPrimeExponentQ(),
					prvKey.getCrtCoefficient());
		}

		eng.init(isEncrypt, keyParams);
		byte[] res = eng.processBlock(data, 0, data.length);

		return res;
	}

	// ******************************************************加解密数据流函数************************************************************************/

	/**
	 * 验证私钥签名
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param pubKey
	 *            公钥
	 * @param sourceData
	 *            签名前数据
	 * @param signData
	 *            签名数据
	 * @return
	 * @throws Exception
	 */
	public boolean verifySign(Mechanism mechanism, JKeyParmater pubKey,
			byte[] sourceData, byte[] signData) throws Exception {
		String mType = mechanism.getMechanismType();
		if (!(mechanism.isSignabled()))
			throw new Exception("8126 　：验证签名操作失败 本操作不支持此种机制类型 " + mType);

		if (mType.equals("RSA/ECB/PKCS1PADDING"))
			try {
				byte[] decData = doCipher(mechanism, pubKey, false, signData);
				return Converts.isEqualArray(decData, sourceData);
			} catch (Exception ex) {
				throw new Exception("8125　：签名操作失败", ex);
			}
		try {
			Signature signature = Signature.getInstance(mechanism
					.getMechanismType(), "BC");
			signature.initVerify(KeyParser.convertPublicKey(pubKey));
			signature.update(sourceData);
			return signature.verify(signData);
		} catch (Exception signature) {
			throw new Exception("8126 　： 验证签名操作失败", signature);
		}
	}

	/**
	 * 生成摘要
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param sourceData
	 *            需要生成摘要的数据
	 * @return
	 * @throws Exception
	 */
	public byte[] digest(Mechanism mechanism, byte[] sourceData)
			throws Exception {
		String mType = mechanism.getMechanismType();
		if (!(mechanism.isDigestabled()))
			throw new Exception("8122 ： 文摘操作失败 本操作不支持此种机制类型 " + mType);

		try {
			MessageDigest m = MessageDigest.getInstance(mType, "BC");
			m.update(sourceData);
			byte[] digest = m.digest();
			return digest;
		} catch (Exception ex) {
			throw new Exception("8122 ：文摘操作失败", ex);
		}
	}

	/**
	 * 生成MAC
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param key
	 *            密钥
	 * @param sourceData
	 *            需要生成MAC的数据
	 * @return
	 * @throws Exception
	 */
	public byte[] mac(Mechanism mechanism, JKeyParmater key, byte[] sourceData)
			throws Exception {
		String mType = mechanism.getMechanismType();
		if ((!(mType.equals("HMac-MD2"))) && (!(mType.equals("HMac-MD5")))
				&& (!(mType.equals("HMac-SHA1")))) {
			throw new Exception("8123 ：MAC操作失败 本操作不支持此种机制类型 " + mType);
		}

		byte[] macData = (byte[]) null;
		try {
			Mac mac = Mac.getInstance(mechanism.getMechanismType(), "BC");
			mac.init(KeyParser.convertSecretKey(key));
			mac.update(sourceData);
			macData = mac.doFinal();
			return macData;
		} catch (Exception ex) {
			throw new Exception("8123 ：MAC操作失败", ex);
		}
	}

	/**
	 * 验证MAC
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param key
	 *            密钥
	 * @param sourceData
	 *            原始数据
	 * @param macData
	 *            MAC数据
	 * @return
	 * @throws Exception
	 */
	public boolean verifyMac(Mechanism mechanism, JKeyParmater key,
			byte[] sourceData, byte[] macData) throws Exception {
		String mType = mechanism.getMechanismType();
		if ((!(mType.equals("HMac-MD2"))) && (!(mType.equals("HMac-MD5")))
				&& (!(mType.equals("HMac-SHA1"))))
			throw new Exception("8124 ：验证MAC操作失败 本操作不支持此种机制类型 " + mType);

		try {
			byte[] tmp = mac(mechanism, key, sourceData);
			return KeyParser.isEqualArray(tmp, macData);
		} catch (Exception ex) {
			throw new Exception("8124 ：验证MAC操作失败", ex);
		}
	}

	/**
	 * 数据签名
	 * 
	 * @param mechanism
	 *            密钥规则
	 * @param prvKey
	 *            私钥
	 * @param sourceData
	 *            需要签名的数据
	 * @return
	 * @throws Exception
	 */
	public byte[] sign(Mechanism mechanism, JKeyParmater prvKey,
			byte[] sourceData) throws Exception {
		String mType = mechanism.getMechanismType();
		if (!(mechanism.isSignabled()))
			throw new Exception("8125 ：签名操作失败 本操作不支持此种机制类型 " + mType);

		byte[] signData = (byte[]) null;

		if (mType.equals("RSA/ECB/PKCS1PADDING"))
			try {
				signData = doCipher(mechanism, prvKey, true, sourceData);
			} catch (Exception ex) {
				throw new Exception("8125 ：签名操作失败", ex);
			}
		else
			try {
				Signature signature = Signature.getInstance(mType, "BC");
				signature.initSign(KeyParser.convertPrivateKey(prvKey));
				signature.update(sourceData);
				signData = signature.sign();
			} catch (Exception signature) {
				throw new Exception("8125 ：签名操作失败", signature);
			}

		return signData;
	}
	
	/**
	 * 根据长度产生随机数
	 * @param mechanism
	 * 				规则
	 * @param length
	 * 				长度
	 * @return
	 * @throws Exception
	 */
	public byte[] generateRandom( int length)
	{
	    SecureRandom sRandom = new SecureRandom();
	    byte[] data = new byte[length];
	    sRandom.nextBytes(data);
	    return data;
	}


	/**
	 * 拼装3DES处理数据，保证数据是8的倍数
	 * @param data				数据源
	 * @return
	 * @throws IOException
	 */
	public byte[] set3DESDateNOPADDING(byte[] data) throws IOException{
		
		int dataLength = data.length%8 ;
		
		if(dataLength != 0){
			byte[] nopaddings = new byte[8 - dataLength];
			byte[] paddings = new byte[8];
			paddings[0] = (byte)0x80;
			System.arraycopy(paddings, 0, nopaddings, 0,8 - dataLength);
			ByteArrayOutputStream bous = new ByteArrayOutputStream();
			bous.write(data);
			bous.write(nopaddings);
			byte[] hashInput = bous.toByteArray();
			bous.close();
			
			return hashInput;
			
		}else{
			return data;
		}
	}
}
