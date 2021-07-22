package com.cybbj.RSAOperator;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import com.cybbj.util.Converts;
public class ParsePubKey {
	static {
		Security.addProvider(new BouncyCastleProvider()); 
	}
 
    public static void getCerInfo(String fileName,String path) throws Exception {
    	X509Certificate oCer = getCertFromFile(fileName,path);
    	//X509Certificate oCer = (X509Certificate) getAppleCertFromBase64String("MIIC3zCCAoOgAwIBAgIFQAA3BocwDAYIKoEcz1UBg3UFADBhMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSAwHgYDVQQDDBdDRkNBIEFDUyBURVNUIFNNMiBPQ0EzMTAeFw0xNzA0MjYxMDQyNDdaFw0yMjA0MjYxMDQyNDdaMIGDMQswCQYDVQQGEwJDTjERMA8GA1UECgwIT0NBMzFTTTIxFTATBgNVBAsMDHNoYW5naGFpVGVjaDEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwtMjEvMC0GA1UEAwwmU0hUZWNoQOS4reWbvemTtuiBlEA4OTEzMTAwMDA3MzYyMzk4QDIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASQu85t2AKXrwlIbbgk8tPW3IXaWke/4v7NgZmEfh8S9vWK+hsFF5t+Z1Q28J1exBzD3dcB03lnFEmnq0KO4fPNo4IBATCB/jBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly8yMTAuNzQuNDIuMTE6ODA4NS9vY3NwX3NlcnZlci9vY3NwLzAfBgNVHSMEGDAWgBQEx7z5WQFpPow0NiBiGDzevLW7DDAMBgNVHRMBAf8EAjAAMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly8yMTAuNzQuNDIuMy9PQ0EzMS9TTTIvY3JsNTcuY3JsMA4GA1UdDwEB/wQEAwIDODAdBgNVHQ4EFgQUH8wAh3aqWf7/TCRdPHSE46fBE9AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADSAAwRQIhAPtYT0hC7UeX3mmJqEQdp7Rscsr65Deafy+c+TV9a4YeAiBAUu9g+qvpbEjTfw5zFbWgNPn3yTFAsIazAD8qKhgckg==");
        SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd");
        //证书版本
        String info = String.valueOf(oCer.getVersion());
        System.out.println("证书版本====" + info);
        // 获得证书序列号
        info = oCer.getSerialNumber().toString(16);
        System.out.println("证书序列号:" + info);
        // 获得证书有效期
        Date beforedate = oCer.getNotBefore();
        info = dateformat.format(beforedate);
        System.out.println("证书生效日期:" + info);
        Date afterdate = oCer.getNotAfter();
        info = dateformat.format(afterdate);
        System.out.println("证书失效日期:" + info);

        // 获得证书主体信息
        info = oCer.getSubjectDN().getName();
        System.out.println("证书拥有者:" + info);
        // 获得证书颁发者信息
        info = oCer.getIssuerDN().getName();
        System.out.println("证书颁发者:" + info);
        // 获得证书签名算法名称
        info = oCer.getSigAlgName();
        System.out.println("证书签名算法:" + info);
        //证书指纹信息
        //System.out.println("证书指纹信息\n" + (DigestUtils.sha1Hex(oCer.getEncoded())));      
        System.out.println("证书公钥信息" + oCer.getPublicKey());
        byte[] oriPublicKeyBt = oCer.getPublicKey().getEncoded();
        System.out.println("证书公钥信息" + Converts.bytesToHexString(oriPublicKeyBt));
        byte[] publicKeyBt = new byte[oriPublicKeyBt.length-27];
        System.arraycopy(oriPublicKeyBt, 27, publicKeyBt, 0, publicKeyBt.length);
        System.out.println("证书公钥信息" + Converts.bytesToHexString(publicKeyBt));
    }
    
    /**
     * 获取公钥X,Y
     * @param fileName	文件名称
     * @return	公钥X,Y的byte数组
     * @throws Exception
     */
    public static Map<String,String> getPublicKeyInfo(String fileName,String path) throws Exception {
    	Map<String,String> map = new HashMap<String,String>();
    	X509Certificate oCer = getCertFromFile(fileName,path); 
        // 获得证书序列号
        String serialNum = oCer.getSerialNumber().toString(16);
        map.put("serialNum", serialNum);
        System.out.println("证书序列号:" + serialNum);
        System.out.println("证书公钥信息" + oCer.getPublicKey());
        byte[] oriPublicKeyBt = oCer.getPublicKey().getEncoded();
        System.out.println("证书公钥信息" + Converts.bytesToHexString(oriPublicKeyBt));
        byte[] publicKeyBt = new byte[oriPublicKeyBt.length-27];
        System.arraycopy(oriPublicKeyBt, 27, publicKeyBt, 0, publicKeyBt.length);
        String publicKeyXY = Converts.bytesToHexString(publicKeyBt);
        map.put("publicKeyXY", publicKeyXY);
        System.out.println("证书公钥信息" + publicKeyXY);
        return map;
    }
    
    /**
     * 将文件中的公钥转换为X509Certificate对象
     * @param fileName 文件名
     * @return	X509Certificate对象
     */
    public static X509Certificate getCertFromFile(String fileName,String path) throws Exception{    	
    	InputStream ins = null;
    	BufferedReader br = null;
    	try {
    		/*String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
        	log.info("rootPath: " + rootPath);
    		rootPath = URLDecoder.decode(rootPath,"utf-8");
        	log.info("URLDecoder.decode rootPath后: " + rootPath);	
            String path = rootPath + File.separator +"certificate" + File.separator + "signature" + File.separator + fileName;*/
    		File file = new File(path+"/"+fileName);
            ins = new FileInputStream(file);

            br = new BufferedReader(new InputStreamReader(ins));
    		String readLine = null;
    		StringBuilder sb = new StringBuilder();
    		while ((readLine = br.readLine()) != null) {
    			if (readLine.charAt(0) == '-') {
    				continue;
    			} else {
    				sb.append(readLine);
    				sb.append('\r');
    			}
    		}
           /* byte[] bt = new byte[ins.available()];
            ins.read(bt);*/
            //创建x.509工厂类
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            //创建证书实例
            X509Certificate x509Certificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(Base64.decode(sb.toString())));
            return x509Certificate;            
		} finally {
			try {
				if (br!=null) {
					br.close();
				}
				if (ins!=null) {
					ins.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}    	
    }
    
    /**
     * 将文件中的公钥直接读取
     * @param fileName 文件名
     * @return	证书信息
     */
    public static String getCertInfoFromFile(String fileName,String path) throws Exception {    	
    	InputStream ins = null;
    	BufferedReader br = null;
    	try {
        	/*String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
        	log.info("rootPath: " + rootPath);
    		rootPath = URLDecoder.decode(rootPath,"utf-8");
        	log.info("URLDecoder.decode rootPath后: " + rootPath);	
            String path = rootPath + File.separator +"certificate" + File.separator + "signature" + File.separator + fileName;*/
    		File file = new File(path + "/" + fileName);
            ins = new FileInputStream(file);

            br = new BufferedReader(new InputStreamReader(ins));
    		String readLine = null;
    		StringBuilder info = new StringBuilder();
    		while ((readLine = br.readLine()) != null) {
    			if (readLine.charAt(0) == '-') {
    				continue;
    			} else {
    				info.append(readLine);
    				//info.append('\r');
    			}
    		}
    		return info.toString();
		} finally {
			try {
				if (br!=null) {
					br.close();
				}
				if (ins!=null) {
					ins.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}    	
    }
    	
    /**
     * 通过base64字符串解析密钥成X509Certificate对象
     * @param cert	base64密钥串
     * @return	X509Certificate对象
     * @throws Exception
     */
    public static X509Certificate getCertFromBase64String(String cert) throws Exception{
        byte [] certificateBytes = Base64.decode(cert.getBytes() );
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509","BC");
        return  (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }
    
    /**
     * 测试代码
     */
    public static void decrytPublicKey() {
    	String base64PublicKey = "MIIC3zCCAoOgAwIBAgIFQAA3BocwDAYIKoEcz1UBg3UFADBhMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSAwHgYDVQQDDBdDRkNBIEFDUyBURVNUIFNNMiBPQ0EzMTAeFw0xNzA0MjYxMDQyNDdaFw0yMjA0MjYxMDQyNDdaMIGDMQswCQYDVQQGEwJDTjERMA8GA1UECgwIT0NBMzFTTTIxFTATBgNVBAsMDHNoYW5naGFpVGVjaDEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwtMjEvMC0GA1UEAwwmU0hUZWNoQOS4reWbvemTtuiBlEA4OTEzMTAwMDA3MzYyMzk4QDIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASQu85t2AKXrwlIbbgk8tPW3IXaWke/4v7NgZmEfh8S9vWK+hsFF5t+Z1Q28J1exBzD3dcB03lnFEmnq0KO4fPNo4IBATCB/jBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly8yMTAuNzQuNDIuMTE6ODA4NS9vY3NwX3NlcnZlci9vY3NwLzAfBgNVHSMEGDAWgBQEx7z5WQFpPow0NiBiGDzevLW7DDAMBgNVHRMBAf8EAjAAMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly8yMTAuNzQuNDIuMy9PQ0EzMS9TTTIvY3JsNTcuY3JsMA4GA1UdDwEB/wQEAwIDODAdBgNVHQ4EFgQUH8wAh3aqWf7/TCRdPHSE46fBE9AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADSAAwRQIhAPtYT0hC7UeX3mmJqEQdp7Rscsr65Deafy+c+TV9a4YeAiBAUu9g+qvpbEjTfw5zFbWgNPn3yTFAsIazAD8qKhgckg==";
    	byte [] certificateBytes = Base64.decode(base64PublicKey.getBytes() );
		System.out.println(Converts.bytesToHexString(certificateBytes));
    }
    
    public static void main(String[] args) {
    	try {
			//Map map = ParsePubKey.getPublicKeyInfo("RSA-server-public.pem","F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
    		Map map = ParsePubKey.getPublicKeyInfo("RSA-server-public.cer","F:/中付支付/ThreeDS/分析资料-自己整理/OPENSSL/个人测试证书");
			System.out.println(map.get("serialNum"));
			System.out.println(map.get("publicKeyXY"));
    		//ParsePubKey.getCerInfo("public.cer");
    		//X509Certificate x509Certificate = getCertFromFile("RSA-server-public.cer","");
    		//X509Certificate x509Certificate = getCertFromFile("EC-Server.pem");
    		//getCerInfo("EC-Server.pem");
    		//getCerInfo("RSA-server-public.cer","");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
