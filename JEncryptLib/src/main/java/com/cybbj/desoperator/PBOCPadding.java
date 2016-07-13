package com.cybbj.desoperator;

/**
 * 
 * PBOCPadding: 依据PBOC规范补位
 * 
 * @version 1.0
 * @author zengqiaowang
 * @modified 2014-4-15 v1.0 zengqiaowang 新建
 */
public class PBOCPadding {
	
	/**
	 * 
	 * addPaddingPBOC: 依据PBOC规范补位方法
	 *
	 * @param paramArrayOfByte  参数byte数组
	 * @return 处理后数组
	 * @throws
	 */
	public static byte[] addPaddingPBOC(byte[] paramArrayOfByte){
		byte[] padding = new byte[8];
		padding[0] = (byte)0x80;
		int i = paramArrayOfByte.length % 8;
		byte[] arrayOfByte;
		int j = 0;
		if(i == 0){
			arrayOfByte = new byte[paramArrayOfByte.length + padding.length];
			System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, paramArrayOfByte.length);
			System.arraycopy(padding, 0, arrayOfByte, paramArrayOfByte.length, padding.length);
		}else{
			j = 8 - i;
			arrayOfByte = new byte[paramArrayOfByte.length + j];
			System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, paramArrayOfByte.length);
			System.arraycopy(padding, 0, arrayOfByte, paramArrayOfByte.length, j);
		}
		return arrayOfByte;
	}
	
	public static byte[] unPaddingPBOC(byte[] paramArrayOfByte){
		int k = 0;
		byte[] padding = new byte[8];
		System.arraycopy(paramArrayOfByte, paramArrayOfByte.length - 8, padding, 0, padding.length);
		for (int i = 0 ; i < padding.length ; i++)
			if (padding[i] == -128) {
				k = i;
				break;
			}
		int m = paramArrayOfByte.length - (8 - k);
		byte[] arrayOfByte = new byte[m];
		System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, m);
		return arrayOfByte;
	}

	
	public static byte[] addPaddingPKCS(byte[] paramArrayOfByte){
		int i = paramArrayOfByte.length % 8;
		byte[] padding;
		switch(i){
			case 0:
				padding = new byte[]{(byte)0x88,(byte)0x88,(byte)0x88,(byte)0x88,(byte)0x88,(byte)0x88,(byte)0x88,(byte)0x88};
	            break;
	        case 1:
	        	padding = new byte[]{(byte)0x77,(byte)0x77,(byte)0x77,(byte)0x77,(byte)0x77,(byte)0x77,(byte)0x77};
	            break;
	        case 2:
	        	padding = new byte[]{(byte)0x66,(byte)0x66,(byte)0x66,(byte)0x66,(byte)0x66,(byte)0x66};
	            break;
	        case 3:
	        	padding = new byte[]{(byte)0x55,(byte)0x55,(byte)0x55,(byte)0x55,(byte)0x55};
	            break;
	        case 4:
	        	padding = new byte[]{(byte)0x44,(byte)0x44,(byte)0x44,(byte)0x44};
	            break;
	        case 5:
	        	padding = new byte[]{(byte)0x33,(byte)0x33,(byte)0x33};
	            break;
	        case 6:
	        	padding = new byte[]{(byte)0x22,(byte)0x22};
	            break;
	        case 7:
	        	padding = new byte[]{(byte)0x11};
	            break;
	        default:
	            throw new Error("算法 类型（External） 输入错误");
		}
		byte[] arrayOfByte = new byte[paramArrayOfByte.length + 8 - i];
		
		System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, paramArrayOfByte.length);
		System.arraycopy(padding, 0, arrayOfByte, paramArrayOfByte.length, padding.length);
		return arrayOfByte;
	}
	
	public static byte[]unPaddingPKCS(byte[] paramArrayOfByte){
		byte[] padding = new byte[8];
		System.arraycopy(paramArrayOfByte, paramArrayOfByte.length - 8, padding, 0, padding.length);
		
		byte i = padding[7];
		int k = 0 ;
		switch(i){
			case (byte)0x88:
				k = 8;
	            break;
	        case (byte)0x77:
	        	k = 7;
	            break;
	        case (byte)0x66:
	        	k = 6;
	            break;
	        case (byte)0x55:
	        	k = 5;
	            break;
	        case (byte)0x44:
	        	k = 4;
	            break;
	        case (byte)0x33:
	        	k = 3;
	            break;
	        case (byte)0x22:
	        	k = 2;
	            break;
	        case (byte)0x11:
	        	k = 1;
	            break;
	        default:
	            throw new Error("算法 类型（External） 输入错误");
		}
		
		byte[] arrayOfByte = new byte[paramArrayOfByte.length - k];
		System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, arrayOfByte.length);
		
		return arrayOfByte;
	}
}