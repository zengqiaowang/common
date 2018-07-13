package com.cybbj.desoperator;

import java.io.InputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.cybbj.JKeyParmater;
import com.cybbj.KeyParser;
import com.cybbj.Mechanism;
import com.cybbj.contants.ErrorCode;
import com.cybbj.keyOperator.KeyGenerate;
import com.cybbj.param.CBCParam;
import com.cybbj.util.Converts;

/**
 * 
 * @author administrator
 * 
 *         DES算法操作类
 */
public class DESGenerate extends KeyGenerate{

	/**
	 * 随机生成一般的3DES密钥
	 * @param mechanism
	 * 				密钥规则
	 * @param keyLength
	 * 				长度
	 * @return
	 * @throws Exception
	 */
	public JKeyParmater generateKey(Mechanism mechanism, int keyLength)
			throws Exception {
		String mType = mechanism.getMechanismType();
		if ((!(mType.equals("DES"))) && (!(mType.equals("DESede")))
				&& (!(mType.equals("RC2"))) && (!(mType.equals("RC4")))
				&& (!(mType.equals("CAST5"))) && (!(mType.equals("IDEA")))
				&& (!(mType.equals("AES"))))
			throw new Exception(ErrorCode.GENERATEDESFAIL +" : 产生对称密钥操作失败 本操作不支持此种机制类型 " + mType);

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(mechanism.getMechanismType(), "BC");
			keyGen.init(keyLength);
			SecretKey key = keyGen.generateKey();
			return new JKeyParmater(key.getAlgorithm(), key.getEncoded());
		} catch (Exception ex) {
			throw new Exception(ErrorCode.GENERATEDESFAIL +": 产生对称密钥操作失败", ex);
		}
	}
	
	/**
	 * 生成符合PBOC方式的3DES密钥	
	 * @return
	 * @throws Exception
	 */
	public JKeyParmater generate3DESKey()throws Exception {
		Mechanism mechanism = new Mechanism("DESede");
		String mType = mechanism.getMechanismType();
		if ((!(mType.equals("DES"))) && (!(mType.equals("DESede")))
				&& (!(mType.equals("RC2"))) && (!(mType.equals("RC4")))
				&& (!(mType.equals("CAST5"))) && (!(mType.equals("IDEA")))
				&& (!(mType.equals("AES"))))
			throw new Exception(ErrorCode.GENERATEDESFAIL +" : 产生对称密钥操作失败 本操作不支持此种机制类型 " + mType);

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(mechanism.getMechanismType(), "BC");
			keyGen.init(128);
			SecretKey key = keyGen.generateKey();
			return new JKeyParmater(key.getAlgorithm(), get3DESKey(key.getEncoded()));
		} catch (Exception ex) {
			throw new Exception(ErrorCode.GENERATEDESFAIL +" : 产生对称密钥操作失败", ex);
		}
	}
	
	/**
	 * 减去PADDING
	 * @param enKey
	 * 				密钥
	 * @param sourceData
	 * 				数据。当数据是8的倍数，不在数据后面增加80 00 …
	 * 					    当数据不是8的倍数,在数据后面增加80 00 …	,增加后的数据是8的倍数
	 */
	public byte[] decryptByCBCNOPADDING(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/CBC/NOPADDING",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		return decryptData;
	}
	/**
	 * 减去PADDING
	 * @param enKey
	 * 				密钥
	 * @param sourceData
	 * 				数据。当数据是8的倍数，不在数据后面增加80 00 …
	 * 					    当数据不是8的倍数,在数据后面增加80 00 …	,增加后的数据是8的倍数
	 */
	public byte[] decryptByECBNOPADDING(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/ECB/NOPADDING",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		return decryptData;
	}
	
	public byte[] decryptByCBCPKCS7Padding(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		return decryptData;
	}
	public byte[] decryptByECBPKCS7Padding(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/ECB/PKCS7Padding",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		return decryptData;
	}
	
	/**
	 * 按照PBOC的方式增加PADDING
	 * @param enKey
	 * 				密钥
	 * @param sourceData
	 * 				数据。
	 * 				当数据是8的倍数，不在数据后面增加80 00 …
	 * 				当数据不是8的倍数,在数据后面增加80 00 …,增加后的数据是8的倍数
	 */
	public byte[] encryptByCBCNOPADDING(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/CBC/NOPADDING",new CBCParam());
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	public byte[] encryptByECBNOPADDING(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/ECB/NOPADDING",new CBCParam());
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	
	public byte[] encryptByCBCPKCS7Padding(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding",new CBCParam());
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	public byte[] encryptByECBPKCS7Padding(JKeyParmater enKey,byte[] sourceData) throws Exception{
		Mechanism mechanism = new Mechanism("DESede/ECB/PKCS7Padding",new CBCParam());
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	
	/**
	 * 按照PBOC的方式增加PADDING
	 * @param key
	 * 				密钥
	 * @param sourceData
	 * 				数据。
	 * 				当数据是8的倍数，不在数据后面增加80 00 …
	 * 				当数据不是8的倍数,在数据后面增加80 00 …,增加后的数据是8的倍数
	 */
	public byte[] encryptByCBCNOPADDING(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/CBC/NOPADDING",new CBCParam());
//		byte[] sourcePadding = PBOCPadding.addPaddingPKCS(sourceData);
//		addPadding(sourceData);
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	public byte[] encryptByECBNOPADDING(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/ECB/NOPADDING",new CBCParam());
//		byte[] sourcePadding = PBOCPadding.addPaddingPKCS(sourceData);
//		addPadding(sourceData);
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	
	public byte[] encryptByCBCPKCS7Padding(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding",new CBCParam());
//		addPadding(sourceData);
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	public byte[] encryptByECBPKCS7Padding(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/ECB/PKCS7Padding",new CBCParam());
//		addPadding(sourceData);
		byte[] encryptData = super.encrypt(mechanism, enKey, sourceData);
		return encryptData;
	}
	
	/**
	 * 减去PADDING
	 * @param key
	 * 				密钥
	 * @param sourceData
	 * 				数据。当数据是8的倍数，不在数据后面增加80 00 …
	 * 					    当数据不是8的倍数,在数据后面增加80 00 …	,增加后的数据是8的倍数
	 */
	public byte[] decryptByCBCNOPADDING(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/CBC/NOPADDING",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		
		byte[] decryptPadding = PBOCPadding.unPaddingPKCS(decryptData);
		System.out.println("解密后的数据：" + Converts.bytesToHexString(decryptPadding));
		return decryptPadding;
	}
	public byte[] decryptByECBNOPADDING(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/ECB/NOPADDING",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		
		byte[] decryptPadding = PBOCPadding.unPaddingPKCS(decryptData);
		System.out.println("解密后的数据：" + Converts.bytesToHexString(decryptPadding));
		return decryptPadding;
	}
	public byte[] decryptByCBCPKCS7Padding(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		
		System.out.println("解密后的数据：" + Converts.bytesToHexString(decryptData));
		return decryptData;
	}
	public byte[] decryptByECBPKCS7Padding(byte[] key , byte[] sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/ECB/PKCS7Padding",new CBCParam());
		byte[] decryptData = super.decrypt(mechanism, enKey, sourceData);
		
		System.out.println("解密后的数据：" + Converts.bytesToHexString(decryptData));
		return decryptData;
	}
	
	public byte[] encryptFileByCBCPKCS7Padding(byte[] key , InputStream sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding",new CBCParam());
		return super.encrypt(mechanism, enKey, sourceData);
	}
	public byte[] encryptFileByECBPKCS7Padding(byte[] key , InputStream sourceData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater enKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/ECB/PKCS7Padding",new CBCParam());
		return super.encrypt(mechanism, enKey, sourceData);
	}
	
	public byte[] decryptFileByCBCPKCS7Padding(byte[] key ,InputStream encryptedData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater deKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding",new CBCParam());
		return super.decrypt(mechanism, deKey, encryptedData);
		
	}
	
	public byte[] decryptFileByECBPKCS7Padding(byte[] key ,InputStream encryptedData) throws Exception{
		byte[] _3desKey = get3DESKey(key);
		JKeyParmater deKey = new JKeyParmater("DESede",_3desKey);
		Mechanism mechanism = new Mechanism("DESede/ECB/PKCS7Padding",new CBCParam());
		return super.decrypt(mechanism, deKey, encryptedData);
		
	}
	
	
	/**
	 * 计算MAC
	 * @param processKey
	 * @param arrByte
	 * @return
	 * @throws Exception
	 */
	public byte[] getCBCMac(byte[] processKey,byte[] arrByte) throws Exception{
		
		byte[] _3desKey = get3DESKey(processKey);
		
		byte[] singleDESKey = new byte[8];
		
		for(int i = 0 ; i<8 ; i++){
			singleDESKey[i] =  _3desKey[i];
		}
		
		byte[] arrPadding = PBOCPadding.addPaddingPKCS(arrByte);
		//初始化3DES运算条件
		JKeyParmater des = new JKeyParmater("DESede",_3desKey);
		Mechanism desMechanism = new Mechanism("DESede/ECB/NOPADDING",new CBCParam());
		//初始化单DES运算条件
		JKeyParmater singledes = new JKeyParmater("DES",singleDESKey);
		Mechanism singledesMechanism = new Mechanism("DES/ECB/NOPADDING",new CBCParam());
		
		byte[] cbcKey = new byte[8];
		if(arrPadding.length%8 == 0){
			if(arrPadding.length > 8){
				int count = arrPadding.length/8;
				byte[] tempByte = new byte[8];
				byte[] orxByte = new byte[8];
				for(int i = 0 ; i< count;i++){
					for(int j = 0 ; j<8;j++){
						tempByte[j] = arrPadding[8*i + j];
						orxByte[j] = (byte)(orxByte[j] ^ tempByte[j]);
					}
					if(i == count-1){
						orxByte = encrypt(desMechanism, des, orxByte);
					}else{
						orxByte = encrypt(singledesMechanism, singledes, orxByte);
					}
				}
				cbcKey = orxByte;
			}else{
				cbcKey = encrypt(desMechanism, des,arrPadding);
			}
		}else{
			throw new Error("getCBCMac 加密的数据必须是8的倍数！");
		}
		return cbcKey;
	}
	
	/**
	 * 验证mac
	 * @param processKey
	 * @param arrByte
	 * @param mac
	 * @return
	 * @throws Exception
	 */
	public boolean verifyMac(byte[] processKey,byte[] arrByte,byte[] mac) throws Exception{
		byte[] v_mac = getCBCMac(processKey,arrByte);
		
		return KeyParser.isEqualArray(mac, v_mac);
	}
	
	/**
	 * 从指定字符串生成密钥，密钥所需的字节数组长度为24位 如果密钥长度是16位，就将前8为的密钥放到数组的后8位 如果密钥长度大于24位，截取前24位
	 * 
	 * @param _3desKey
	 * @return
	 */
	public byte[] get3DESKey(byte[] _3desKey) {
		// 创建一个空的24位字节数组（默认值为0）
		byte[] arrB = new byte[24];
		if (_3desKey.length == 16) {
			for (int i = 0; i < _3desKey.length; i++) {
				arrB[i] = _3desKey[i];
				if (i <= 7) {
					arrB[_3desKey.length + i] = _3desKey[i];
				}
			}
		} else if (_3desKey.length >= 24) {
			for (int i = 0; i < _3desKey.length; i++) {
				arrB[i] = _3desKey[i];
			}
		} else {
			throw new IllegalStateException("3DES的密钥长度不对！");
		}
		// 生成密钥
//		Key key = new javax.crypto.spec.SecretKeySpec(arrB, "DESede");
		return arrB;
	}

	
}
