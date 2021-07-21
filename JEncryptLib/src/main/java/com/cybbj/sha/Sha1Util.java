package com.cybbj.sha;

import java.security.MessageDigest;

public class Sha1Util {
	/**
	 * SHA1 算法
	 * @param str
	 * @return	str SHA1之后的byte[]
	 * @throws Exception
	 */
	public static byte[] getSha1(String str) throws Exception{
	    if (null == str || 0 == str.length()){
	        return null;
	    }
    	MessageDigest mdTemp = MessageDigest.getInstance("SHA1");
        mdTemp.update(str.getBytes("UTF-8"));
        byte[] md = mdTemp.digest();
        return md;
	}
}
