package com.cybbj.RSAOperator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;

import com.cybbj.base64.Base64Util;
import com.cybbj.util.Converts;

public class ParsePriKey {

    public static String getPriKeyInfo(String fileName,String path) throws Exception {
    	FileInputStream fileInputStream = null;
    	InputStreamReader inputStreamReader = null;
    	BufferedReader bufferedReader = null;
    	String hexPriKey = null;
    	try {
        	/*String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
        	try {
    			rootPath = URLDecoder.decode(rootPath,"utf-8");
    		} catch (UnsupportedEncodingException e1) {
    			e1.printStackTrace();
    		}
            String path = rootPath + File.separator +"certificate" + File.separator + "signature" + File.separator + fileName;*/
        	File file = new File(path+"/"+fileName);
        	fileInputStream = new FileInputStream(file);
        	inputStreamReader = new InputStreamReader(fileInputStream);
        	bufferedReader = new BufferedReader(inputStreamReader);
          	//String base64PriKey = bufferedReader.readLine();
          	
    		String readLine = null;
    		StringBuilder base64PriKey = new StringBuilder();
    		while ((readLine = bufferedReader.readLine()) != null) {
    			if (readLine.charAt(0) == '-') {
    				continue;
    			} else {
    				base64PriKey.append(readLine);
    				base64PriKey.append('\r');
    			}
    		}
          	
          	if (base64PriKey!=null && base64PriKey.length()>0) {
          		hexPriKey = Converts.bytesToHexString(Base64Util.base64Decode(base64PriKey.toString().trim().getBytes("UTF-8")));
          	}          	
		} finally {
			try {
				if (bufferedReader!=null) {
					bufferedReader.close();
				}
				if (inputStreamReader!=null) {
					inputStreamReader.close();
				}
				if (fileInputStream!=null) {
					fileInputStream.close();
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}			
		}    	
      	return hexPriKey;
    }
    
    /**
     * 解析RSA PKCS8格式的私钥
	 * @param fileName	待解析的私钥文件名
	 * @param type	signature/crypt
	 * @return	PrivateKey
     */
	public static PrivateKey getRsaPKCS8PrivateKey(String fileName,String path) throws Exception {
		PrivateKey privateKey = null;
    	/*String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		rootPath = URLDecoder.decode(rootPath,"utf-8");
        String path = rootPath + File.separator +"certificate" + File.separator + type + File.separator + fileName;*/
		Base64 base64 = new Base64();
		byte[] buffer = base64.decode(getPem(path+"/"+fileName));
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}
	
	/**
	 * 读入私钥文件中的私钥数据
	 * @param path
	 * @return
	 * @throws Exception
	 */
	private static String getPem(String path) throws Exception {
		StringBuilder info = new StringBuilder();
		FileInputStream fin = null;
		BufferedReader br = null;
		try {
			fin = new FileInputStream(path);
			br = new BufferedReader(new InputStreamReader(fin));
			String readLine = null;
			while ((readLine = br.readLine()) != null) {
				if (readLine.charAt(0) == '-') {
					continue;
				} else {
					info.append(readLine);
					//sb.append('\r');
				}
			}
			fin.close();
			
		} finally {
			br.close();
			fin.close();
		}
		return info.toString();
	}
    
	/**
	 * 解析RSA PKCS1格式的RSA私钥
	 * @param fileName	待解析的私钥文件名
	 * @param type	signature/crypt
	 * @return	PrivateKey
	 */
	public static PrivateKey getRsaPKCS1PrivateKey(String fileName,String path) throws Exception {
		PrivateKey priKey = null;
    	/*String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		rootPath = URLDecoder.decode(rootPath,"utf-8");
        String path = rootPath + File.separator +"certificate" + File.separator + type + File.separator + fileName;*/
		Base64 base64 = new Base64();
		byte[] buffer = base64.decode(getPem(path+"/"+fileName));
		 // 取得私钥  for PKCS#1
        RSAPrivateKeyStructure asn1PrivKey = new RSAPrivateKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(buffer));
        RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        priKey = keyFactory.generatePrivate(rsaPrivKeySpec);	        
		return priKey;
	}
	
	/**
	 * 解析EC私钥信息
	 * @param fileName	待解析的私钥文件名
	 * @param type	signature/crypt
	 * @return	PrivateKey
	 */
	public static PrivateKey getECPrivateKey(String fileName,String path) throws Exception {
		PrivateKey privateKey = null;
    	/*String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		rootPath = URLDecoder.decode(rootPath,"utf-8");
        String path = rootPath + File.separator +"certificate" + File.separator + type + File.separator + fileName;*/
		//PEMReader pemReader = new PEMReader(new FileReader("G:\\install_soft\\OpenSSL-Win64\\SSL_test\\EC-server2.key"));
		PEMReader pemReader = new PEMReader(new FileReader(path+"/"+fileName));
		Security.addProvider(new BouncyCastleProvider());
		KeyPair keyPair = (KeyPair) pemReader.readObject();
		privateKey = keyPair.getPrivate();
		//byte[] buffer = Base64.getDecoder().decode(getPem(path));
		return privateKey;
	}
	
    public static void main(String[] args) {
    	try {
			//PrivateKey privateKey = getRsaPKCS8PrivateKey("RSA-pkcs8_server-key.pem","F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
    		//PrivateKey privateKey = getRsaPKCS1PrivateKey("RSA-server-key.pem","F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
    		PrivateKey privateKey = getECPrivateKey("EC-Server2.key","F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
    	} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("");
	}
}
