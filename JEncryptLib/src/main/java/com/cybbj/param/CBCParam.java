package com.cybbj.param;

public class CBCParam {
	private byte[] iv;

	  public CBCParam()
	  {
	    this.iv = new byte[8];
//	    SecureRandom sRandom = new SecureRandom();
//	    sRandom.nextBytes(this.iv);
	  }

	  public byte[] getIv()
	  {
	    return this.iv;
	  }

	  public void setIv(byte[] iv)
	  {
	    this.iv = iv;
	  }
}
