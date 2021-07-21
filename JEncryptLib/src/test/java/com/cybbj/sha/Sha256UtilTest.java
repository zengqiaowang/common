package com.cybbj.sha;

import org.junit.Test;

public class Sha256UtilTest {

	@Test
	public void testGetSHA256Str() {
		String str = "";
		try {
			str = Sha256Util.getSHA256Str("appleM00003A00000001100MYR123456789123456789");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(str);
	}
}
