/**   
 * 类名：ErrorCode
 *
 */
package com.cybbj.contants;

/** 
 * ErrorCode: TODO请填写类描述
 * 
 * @version 1.0
 * @author 15989
 * @modified 2016-7-13 v1.0 15989 新建 
 */
public class ErrorCode {

	/**
	 * 8111:产生非对称密钥对失败
	 */
	public final static int GENERATEKEYPAIRFAIL = 8111;
	
	/**
	 * 8801:加密机连接不上
	 */
	public final static int CONNHSMFAIL = 8801;
	
	
	/**
	 * 8802:加密机产生非对称密钥失败
	 */
	public final static int HSMGENERATERSAFAIL = 8802;
	
	/**
	 * 8110:产生对称密钥操作失败
	 */
	public final static int GENERATEDESFAIL = 8110;
	
	/**
	 * 8133:公钥转换失败 密钥类型不合法
	 */
	public final static int PUBKEYCONVFAIL = 8133;
	
	/**
	 * 8130:密钥转换操作失败 密钥类型不合法
	 */
	public final static int KEYCONVFAIL = 8130;
	
	/**
	 * 8131:对称密钥转换失败
	 */
	public final static int DCKEYCONVFAIL = 8131;
	
	/**
	 * 8132:私钥转换失败
	 */
	public final static int PRIKEYCONVFAIL = 8132;
}

