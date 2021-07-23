package com.cybbj.sm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import com.cybbj.base64.Base64Util;
import com.cybbj.contants.CommonContants;

/**
 * 使用前需注意SM2类中ecc_param是使用测试环境的还是正式环境的
 * @author zengqiaowang
 *
 */
public class SM2Utils {
	//生成随机秘钥对
	public static void generateKeyPair() throws Exception{
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		System.out.println("公钥:" + Util.byteToHex(publicKey.getEncoded()));
		System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
		//System.out.println("公钥明文: "+new String(Util.hexToByte(Util.byteToHex(publicKey.getEncoded())), "UTF-8"));
	}
	
	//数据加密
	public static String encrypt(byte[] publicKey, byte[] data) throws Exception {
		String base64Str = "";
		if (publicKey == null || publicKey.length == 0)
		{
			return null;
		}
		
		if (data == null || data.length == 0)
		{
			return null;
		}
		
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);
		
		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
		
		ECPoint c0 = cipher.init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		
		String c0hexStr=Util.getHexString(c0.getEncoded());
//			System.out.println("c1hexStr:"+c0hexStr);
//			System.out.println("c1hexStr:"+c0hexStr.substring(2));
//			System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));
//			System.out.println("C2 " + Util.byteToHex(source));
//			System.out.println("C3 " + Util.byteToHex(c3));
		//C1 C2 C3拼装成加密字串
		//银行加密机截取2位04--工行原稿
		//byte[] c1=Util.hexToByte(c0hexStr.substring(2));
		//银联刷脸需要04
		byte[] c1=Util.hexToByte(c0hexStr);
		byte[] data1=new byte[c1.length+source.length+c3.length];
		System.arraycopy(c1, 0, data1, 0, c1.length);
		System.arraycopy(c3, 0, data1, c1.length, c3.length);
		System.arraycopy(source, 0, data1, c1.length+c3.length, source.length);
		
		base64Str = new String(Base64Util.base64Encode(data1),CommonContants.DEFAULT_CHARACTER);
		//System.out.println("encode Base64密文---:"+base64Str);
		//System.out.println("---:"+Util.byteToHex(data1));
		
		//return Util.byteToHex(c1.getEncoded()).substring(2) + Util.byteToHex(c3)+Util.byteToHex(source);
		return base64Str;
	}
	
	//数据解密16进制字符串
	public static byte[] decryptBase64(byte[] privateKey, String encryptedDataBase64) throws Exception{
		byte[] ret = null;
		/*BASE64Decoder decoder = new BASE64Decoder();
	    byte[] bytes = decoder.decodeBuffer(encryptedDataBase64);*/
		byte[] bytes = Base64Util.base64Decode(encryptedDataBase64.getBytes(CommonContants.DEFAULT_CHARACTER));
	    String encryptedData= Util.byteToHex(bytes);
	    System.out.println("sm2 encryptedData--"+encryptedData);
	    //补全04
	    //ret = decryptString(privateKey, "04"+encryptedData);
	    ret = decryptString(privateKey, encryptedData);
		return ret;
	}
	
	//数据解密16进制字符串
	public static byte[] decryptString(byte[] privateKey, String encryptedData) throws Exception{
		byte[] bt = null;
		String c1=encryptedData.substring(0,130);
		String c3=encryptedData.substring(130,130+64);
		String c2=encryptedData.substring(130+64);
		encryptedData=c1+c2+c3;
		bt = decrypt(privateKey, Util.hexToByte(encryptedData));
		return bt;
	}
	
	//数据解密
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws Exception {
		byte[] c2 = null;
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}
		
		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}
		//加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***分解加密字串
		 * （C1 = C1标志位2位 + C1实体部分128位 = 130）
		 * （C3 = C3实体部分64位  = 64）
		 * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0,130));
		int c2Len = encryptedData.length - 97;
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));
		
		c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		
		//通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		//返回解密结果
		return c2;
	}
	
	public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (sourceData == null || sourceData.length == 0)
		{
			return null;
		}
		byte[] signdata = null;
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(privateKey);
		System.out.println("userD: " + userD.toString(16));
		System.out.println("");
		
		ECPoint userKey = sm2.ecc_point_g.multiply(userD);
		System.out.println("椭圆曲线点X: " + userKey.getX().toBigInteger().toString(16));
		System.out.println("椭圆曲线点Y: " + userKey.getY().toBigInteger().toString(16));
		System.out.println("");
		
		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		System.out.println("SM3摘要Z: " + Util.getHexString(z));
	    System.out.println("");
	    
	    System.out.println("M: " + Util.getHexString(sourceData));
		System.out.println("");
		
		sm3.update(z, 0, z.length);
	    sm3.update(sourceData, 0, sourceData.length);
	    byte[] md = new byte[32];
	    sm3.doFinal(md, 0);
	    
	    System.out.println("SM3摘要值: " + Util.getHexString(md));
	    System.out.println("");
	    
	    SM2Result sm2Result = new SM2Result();
	    sm2.sm2Sign(md, userD, userKey, sm2Result);
	    System.out.println("r: " + sm2Result.r.toString(16));
	    System.out.println("s: " + sm2Result.s.toString(16));
	    System.out.println("");
	    
	    DERInteger d_r = new DERInteger(sm2Result.r);
	    DERInteger d_s = new DERInteger(sm2Result.s);
	    ASN1EncodableVector v2 = new ASN1EncodableVector();
	    v2.add(d_r);
	    v2.add(d_s);
	    DERObject sign = new DERSequence(v2);
	    signdata = sign.getDEREncoded();		
		return signdata;
	}
	
	@SuppressWarnings("unchecked")
	public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData) throws IOException
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return false;
		}
		
		if (sourceData == null || sourceData.length == 0)
		{
			return false;
		}
		
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
		
		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
	    byte[] md = new byte[32];
	    sm3.doFinal(md, 0);
	    System.out.println("SM3摘要值: " + Util.getHexString(md));
	    System.out.println("");
		
	    ByteArrayInputStream bis = new ByteArrayInputStream(signData);
	    ASN1InputStream dis = new ASN1InputStream(bis);
	    DERObject derObj = dis.readObject();
	    Enumeration<DERInteger> e = ((ASN1Sequence) derObj).getObjects();
	    BigInteger r = ((DERInteger)e.nextElement()).getValue();
	    BigInteger s = ((DERInteger)e.nextElement()).getValue();
	    SM2Result sm2Result = new SM2Result();
	    sm2Result.r = r;
	    sm2Result.s = s;
	    System.out.println("r: " + sm2Result.r.toString(16));
	    System.out.println("s: " + sm2Result.s.toString(16));
	    System.out.println("");
	    
	    
	    sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
        return sm2Result.r.equals(sm2Result.R);
	}
	
	public static void main(String[] args) throws Exception 
	{		
		//生成密钥对
		generateKeyPair();
/*		System.out.println("sm2算法验证");
		String plainText = "encryption standard111";
		System.out.println("明文:"+plainText);
		byte[] sourceData = plainText.getBytes();
//		
		String prik = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
		String pubk ="04435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
//				 
//		
		System.out.println("国密规范公钥16进制明文:"+pubk);
		System.out.println("国密规范私钥16进制明文:"+prik);
		*//**********************  加解密    *************************//*
		System.out.println("公钥加密: ");
		String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
		//cipherText="EHY7Z+gDnFZYUWrvBxnLF19Hw6RJz6/QCix7gIfMK9WXJ3gpCTMwWdzvKiWH1exH7coYzQYcA85ZIgqPV4CLdQt3OCxU1Ci2ecSGjj/FkpqxtXB4HfbrejSrBCoHGaREvMPe8YNbopXyvGqQXIk7BA==";
		System.out.println("原始密文:"+cipherText);
		plainText = Util.getHexString(SM2Utils.decryptBase64(Util.hexToByte(prik), cipherText));
		//plainText = Util.getHexString(SM2Utils.decryptString(Util.hexToByte(prik), "04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B89C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D650053A89B41C418B0C3AAD00D886C00286467"));
		System.out.println("私钥解密(HEX形式)2: "+plainText);
		System.out.println("私钥解密(明文形式)2: " +new String(SM2Utils.decryptBase64(Util.hexToByte(prik), cipherText)));
			
		*//**********************  签名验签    *************************//*
		// 国密规范测试用户ID
		String userId = "ALICE123@YAHOO.COM";
		System.out.println("签名: ");
		byte[] c = SM2Utils.sign(userId.getBytes(), Util.hexToByte(prik), sourceData);
		System.out.println("sign: " + Util.getHexString(c));
		System.out.println("");
		
		System.out.println("验签: ");
		boolean vs = SM2Utils.verifySign(userId.getBytes(), Util.hexToByte(pubk), sourceData, c);
		System.out.println("验签结果: " + vs);
		System.out.println("");
		
		System.out.println(Util.getHexString(SecureUtil.base64Decode("TY+0z36l0zfDdgXpl/Lb2v1ZsKnDQgDpm14hOcKSLekWJXKkFSVfItAMHIVFzvBAPI4aCb2eUF3VyjWA0A1kKA==".getBytes())));
	*/
	}
}
