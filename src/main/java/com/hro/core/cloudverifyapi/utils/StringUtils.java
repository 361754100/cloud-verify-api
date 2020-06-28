package com.hro.core.cloudverifyapi.utils;

import java.util.UUID;

/**
 * 字符串工具类
 * @author Mojianzhang
 * 2017年9月5日
 */
public class StringUtils extends org.apache.commons.lang3.StringUtils{
	
	/**
	 * 把对象转换为字符串
	 * @param obj
	 * @return
	 */
	public static String toString(Object obj){
		if( obj == null ){
			return "";
		}
		return String.valueOf(obj);
	}
	
	/**
	 * 把对象转换为字符串,且去掉前后空格
	 * @param obj
	 * @return
	 */
	public static String toTrim(Object obj){
		if( obj == null || "".equals(String.valueOf(obj)) ){
			return "";
		}
		return String.valueOf(obj).trim();
	}
	
	public static String getUuid(){
		String uuid = UUID.randomUUID().toString();
		return uuid;
	}

	/**
	 * Convert  byte[] to hex string
	 * @param src is bytes
	 * @return hexString
	 */
	public static String bytesToHexString(byte[] src){
		StringBuilder stringBuilder = new StringBuilder("");
		if (src == null || src.length <= 0) {
			return null;
		}
		for (int i = 0; i < src.length; i++) {
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString();
	}

	/**
	 * Convert hex string to byte[]
	 * @param hexString the hex string
	 * @return byte[]
	 */
	public static byte[] hexStringToBytes(String hexString) {
		if (hexString == null || hexString.equals("")) {
			return null;
		}
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++) {
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return d;
	}

	/**
	 * Convert char to byte
	 * @param c char
	 * @return byte
	 */
	private static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}
}
