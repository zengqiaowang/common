package com.cybbj.param;

import java.security.SecureRandom;

public class PBEParam {
	private byte[] salt;
	  private int iterations;

	  public PBEParam()
	  {
	    this.salt = new byte[8];
	    SecureRandom sRandom = new SecureRandom();
	    sRandom.nextBytes(this.salt);
	    this.iterations = 1000;
	  }

	  public int getIterations()
	  {
	    return this.iterations;
	  }

	  public byte[] getSalt()
	  {
	    return this.salt;
	  }

	  public void setSalt(byte[] salt)
	  {
	    this.salt = salt;
	  }

	  public void setIterations(int iterations)
	  {
	    this.iterations = iterations;
	  }
}
