/**   
 * 类名：MD5Test
 *
 */
package com.cybbj.md5Operator;

import java.io.UnsupportedEncodingException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import com.cybbj.md5Operator.MD5;

/** 
 * MD5Test: MD5测试类
 * 
 * @version 1.0
 * @author 15989
 * @modified 2016-7-13 v1.0 15989 新建 
 */
public class MD5Test {
	String srcString = "123";
	
	@Before
	public void initData() {
		srcString = "1";
	}
	
	@Test
	public void testMD5EncodeToHex() throws UnsupportedEncodingException {
		System.out.println(MD5.MD5EncodeToHex(this.srcString));
	}
	
	@After
	public void destroy() {
		this.srcString = "";
	}
}
