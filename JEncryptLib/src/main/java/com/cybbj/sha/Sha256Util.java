package com.cybbj.sha;

import java.security.MessageDigest;
import com.cybbj.util.Converts;

/**
 * SHA256 摘要算法工具类
 * @author zengqiaowang
 *
 */
public class Sha256Util {
	
	/**
	 * SHA-256算法
	 * @param param
	 * @return SHA-256 之后,16进制返回
	 * @throws Exception
	 */
	public static String getSHA256Str(String param) throws Exception{
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(param.getBytes("UTF-8"));
		String encodeStr = Converts.bytesToHexString(messageDigest.digest()).toLowerCase();		
		return encodeStr;
	}
}
