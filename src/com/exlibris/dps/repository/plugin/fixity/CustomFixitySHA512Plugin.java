package com.exlibris.dps.repository.plugin.fixity;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.exlibris.dps.repository.plugin.CustomFixityPlugin;
import com.exlibris.core.infra.common.exceptions.logging.ExLogger;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A custom implementation of the CustomFixityPlugin. This implementation will
 * return the SHA512 checksum of the file.
 *
 * @author AlexZ
 */
public class CustomFixitySHA512Plugin implements CustomFixityPlugin {

	private static final String PLUGIN_VERSION_INIT_PARAM = "PLUGIN_VERSION_INIT_PARAM";
	private String pluginVersion = null;
	private boolean result = true;
	static ExLogger log = ExLogger.getExLogger(CustomFixitySHA512Plugin.class);
	private List<String> errors = null;

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.exlibris.dps.repository.plugin.CustomFixityPlugin#getErrors()
	 */
	@Override
	public List<String> getErrors() {
		return errors;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.exlibris.dps.repository.plugin.CustomFixityPlugin#getFixity(java.lang.
	 * String)
	 */
	@Override
	public String getFixity(String filePath, String oldFixity) throws Exception {

		File file = new File(filePath);

		String newFixity = toHex(checksum(file));

		if (!result) { // fail artificially if UI param "fixityScanResult" is set to FALSE
			log.info("SHA-512: \"fixityScanResult\" is set to FALSE");
			log.info("SHA-512 calculated for" + filePath + ". SHA-512 value is really:   " + newFixity);
			newFixity = "DUMMY";
			log.info("SHA-512 calculated for" + filePath + ". SHA-512 value will be now: " + newFixity);
		}

		if ((oldFixity != null) && (!newFixity.equalsIgnoreCase(oldFixity))) {
			errors = new ArrayList();
			errors.add("Fixity mismatch. Old fixity was " + oldFixity + ", new fixity is " + newFixity);
		} else
			log.info("SHA-512 calculated for " + filePath + ". SHA-512 value is: " + newFixity);

		return newFixity;

	}

	@Override
	public String getAlgorithm() {
		return "SHA-512";
	}

	@Override
	public String getAgent() {
		return "Custom fixity SHA-512, Plugin Version " + pluginVersion;
	}

	public void initParams(Map<String, String> initParams) {
		this.pluginVersion = initParams.get(PLUGIN_VERSION_INIT_PARAM);
		// if(!StringUtils.isEmptyString(initParams.get("fixityScanResult"))){
		// result = Boolean.parseBoolean(initParams.get("fixityScanResult").trim());
		// }
	}

	private byte[] checksum(File input) throws IOException {
		FileInputStream in = null;
		try {
			in = new FileInputStream(input);
			MessageDigest digester = MessageDigest.getInstance("SHA-512");
			byte[] block = new byte[4096];
			int length = 0;

			do {
				length = in.read(block);
				if (length > 0) {
					if (digester != null) {
						digester.update(block, 0, length);
					}
				}
			} while (length > 0);
			if (in != null)
				in.close();

			return digester.digest();
		} catch (NoSuchAlgorithmException ex) {
			log.error("SHA-512 not supported");
		} catch (Exception e) {
			log.error("SHA-512 could not be calculated");
			e.printStackTrace();
		}

		finally {
			if (in != null)
				in.close();
		}

		return null;
	}

	private final static char[] hexArray = "0123456789abcdef".toCharArray();

	private static String toHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

}