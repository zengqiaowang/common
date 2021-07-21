package com.cybbj.sha;

import org.junit.Test;

import com.cybbj.util.Converts;

public class Sha1UtilTest {

	@Test
	public void testGetSha1() {
		String str = "南京挺住123456";
		try {
			byte[] btArray = Sha1Util.getSha1(str);
			System.out.println(Converts.bytesToHexString(btArray));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
