package com.hro.core.cloudverifyapi.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * RSA公钥 的工具类
 *
 * RSA是目前最有影响力的公钥加密算法，该算法基于一个十分简单的数论事实：
 * 将两个大素数相乘十分容易，但那时想要对其乘积进行因式分解却极其困难，因此可以将乘积公开作为加密密钥，即公钥，而两个大素数组合成私钥。
 * 公钥是可发布的供任何人使用，私钥则为自己所有，供解密之用。
 *
 * RSA算法实现过程中提到(N,e)是公钥，(N,d)是私钥。既然已经获取到了PublicKey和PrivateKey了，那如何取到N、e、d这三个值呢。
 * 要取到这三个值，首先要将PublicKey和PrivateKey强制转换成RSAPublicKey和RSAPrivateKey。共同的N值可以通过getModulus()获取。
 * 执行RSAPublicKey.getPublicExponent()可以获取到公钥中的e值，执行RSAPrivateKey.getPrivateExponent()可以获取私钥中的d值。
 *
 * 由于程序中动态生成KeyPair对明文加密后生成的密文是不可测的，所以在实际开发中通常在生成一个KeyPair后将公钥和私钥的N、e、d这三个特征值记录下来，在真实的开发中使用这三个特征值再去将PublicKey和PrivateKey还原出来。
 *
 * @author Mojianzhang
 *
 */
public class RsaClientUtil {

	public static final String KEY_ALGORITHM = "RSA";

	private static final String PUBLIC_MODULUS = "MTAwOTI0MzMxODM1NzI1OTM1Mjk2NzUwNjcxNjAwODAyODk5MTkwMTUzODUzNDIyMzI3NjQ3MDI1NjQ2NDA2ODYxNDcyNTI5ODE3MzY5NTUwMzMxMTY3NTMzODY4MjAzNDczNDE5MDk2OTE4Mjc2MDQ2MzYyMTkzNzU0OTgzOTgwNzE4MzQwOTkwNjM0ODgzMTYwODkyOTg3OTY5MDU3NDkyOTIwNzExMjQyNzQxMjEwMDI2NTEwMjQwNTU0NjQzNTQxMDM2MDUwNTExNzE0NDQ2NDczNTE0NTEyNzQ3NDk4NDI2NTQ0ODg3MzMyMDMwMzQyNDg0OTAxODkzNTMzNDMyNDQ1NDk0OTk1MDY5MjI4Mjg3OTg3NTQ1OTk2NzI0MDg3Njg2NjYxMTkzNzc3NjkzMjcx";
	private static final String PUBLIC_EXPONENT = "NjU1Mzc=";

	private static PublicKey pubKey = null;

	private static Logger logger = LoggerFactory.getLogger(RsaClientUtil.class);

	/**
	 * 解码返回byte
	 *
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptBASE64(String key) throws Exception {
		return Base64.getDecoder().decode(key);
	}

	/**
	 * 编码返回字符串
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptBASE64(byte[] key) throws Exception {
		return new String(Base64.getEncoder().encode(key), "UTF-8");
	}


	/**
	 * 使用指定的公钥加密数据。
	 *
	 * @param pubKey 给定的公钥。
	 * @param data 要加密的数据。
	 * @return 加密后的数据。
	 */
	public static byte[] encryptData(byte[] data, PublicKey pubKey) {
		try {
			Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 使用指定的公钥加密数据。
	 *
	 * @param dataStr 要加密的数据。
	 * @return 加密后的数据。
	 */
	public static byte[] encryptData(String dataStr) {
		try {
			byte[] data = dataStr.getBytes("UTF-8");
			Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);

			if(pubKey == null) {
				//1.根据 N、E、D值还原 公钥
				String modulus_str = new String(Base64.getDecoder().decode(PUBLIC_MODULUS.getBytes("UTF-8")));
				String exponent_str = new String(Base64.getDecoder().decode(PUBLIC_EXPONENT.getBytes("UTF-8")));
				pubKey =  RsaClientUtil.restorePublicKey(modulus_str, exponent_str);
			}

			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 根据N、E值 还原公钥
	 *
	 * @param modulus
	 * @param publicExponent
	 * @return
	 */
	public static PublicKey restorePublicKey(String modulus, String publicExponent) {
		try {
			BigInteger bigIntModulus = new BigInteger(modulus);
			BigInteger bigIntPublicExponent = new BigInteger(publicExponent);
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPublicExponent);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pubKey;
	}

	public static void main(String[] args) {
		try {
    		byte[] encryData = RsaClientUtil.encryptData("sperms:20190909114532");
			String baseEncryData = Base64.getEncoder().encodeToString(encryData);
			logger.info("baseEncryData="+ baseEncryData  );
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
