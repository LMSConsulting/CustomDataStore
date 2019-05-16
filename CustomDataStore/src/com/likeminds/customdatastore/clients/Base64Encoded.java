package com.likeminds.customdatastore.clients;

import java.util.Properties;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.slf4j.LoggerFactory;

import com.likeminds.customdatastore.ldap.DefaultLdapDAO;

public class Base64Encoded {
	private final static Logger logger = (Logger) LoggerFactory.getLogger(DefaultLdapDAO.class);
	public static void main(String...strings){
		Properties config = OAuthUtils.getClientConfigProps(OAuthConstants.CONFIG_FILE_PATH);
		String clientId = (String) config.get(OAuthConstants.CLIENT_ID);
		String clientSecret = (String) config.get(OAuthConstants.CLIENT_SECRET);
		logger.debug(encodeCredentials(clientId, clientSecret));
		
	}
	
	public static String encodeCredentials(String username, String password) {
		String cred = username + ":" + password;
		String encodedValue = null;
		byte[] encodedBytes = Base64.encodeBase64(cred.getBytes());
		encodedValue = new String(encodedBytes);
		logger.debug("encodedBytes " + new String(encodedBytes));

		byte[] decodedBytes = Base64.decodeBase64(encodedBytes);
		logger.debug("decodedBytes " + new String(decodedBytes));

		return encodedValue;

	}

}
