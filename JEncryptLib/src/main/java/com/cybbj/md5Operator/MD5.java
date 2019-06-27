/**   
 * 类名：MD5
 *
 */
package com.cybbj.md5Operator;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.cybbj.util.Converts;

/** 
 * MD5: MD5加密类
 * 
 * @version 1.0
 * @author 15989
 * @modified 2016-7-13 v1.0 15989 新建 
 */
public class MD5 {
	/**
	 * MD5加密字符串，返回加密后的16进制字符串
	 * 
	 * @param origin
	 * @return
	 * @throws UnsupportedEncodingException 
	 */
	public static String MD5EncodeToHex(String origin) throws UnsupportedEncodingException {
		return Converts.bytesToHexString(MD5Encode(origin));
	}

	/**
	 * MD5加密字符串，返回加密后的字节数组
	 * 
	 * @param origin
	 * @return
	 * @throws UnsupportedEncodingException 
	 */
	public static byte[] MD5Encode(String origin) throws UnsupportedEncodingException {
		return MD5Encode(origin.getBytes("UTF-8"));
	}

	/**
	 * MD5加密字节数组，返回加密后的字节数组
	 * 
	 * @param bytes
	 * @return
	 */
	public static byte[] MD5Encode(byte[] bytes) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
			return md.digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return new byte[0];
		}

	}
}
