package com.cybbj.base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.junit.Test;

public class Base64UtilTest {
	
	@Test
	public void testBase64Encode() {
		try {
			byte[] bt = Base64Util.base64Encode("测试我爱中华".getBytes("UTF-8"));
			System.out.println(new String(bt,"UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void testBase64Decode() {
		try {
			byte[] bt = Base64Util.base64Decode("5rWL6K+V5oiR54ix5Lit5Y2O".getBytes("UTF-8"));
			System.out.println(new String(bt,"UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
