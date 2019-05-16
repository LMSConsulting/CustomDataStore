package com.likeminds.customdatastore.clients;

import java.util.Properties;

import org.apache.http.HttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.slf4j.LoggerFactory;

import com.likeminds.customdatastore.ldap.DefaultLdapDAO;

//import com.mashape.unirest.http.Unirest;

public class OAuth2Client {

	private final static Logger logger = (Logger) LoggerFactory.getLogger(DefaultLdapDAO.class);

	public static String OauthClient(){
		String accessToken = null;
		//Load the properties file
		Properties config = OAuthUtils.getClientConfigProps(OAuthConstants.CONFIG_FILE_PATH);
		
		//Generate the OAuthDetails bean from the config properties file
		OAuth2Details oauthDetails = OAuthUtils.createOAuthDetails(config);
		
		//Validate Input
		if(!OAuthUtils.isValidInput(oauthDetails)){
			logger.debug("Please provide valid config properties to continue.");
			System.exit(0);
		}
		
		//Determine operation
		if(oauthDetails.isAccessTokenRequest()){
			//Generate new Access token
			accessToken = OAuthUtils.getAccessToken(oauthDetails);
			if(OAuthUtils.isValid(accessToken)){
				logger.debug("Successfully generated Access token for client_credentials grant_type: "+accessToken);
				// Testing 
				/*
				 * HttpResponse response = (HttpResponse)
				 * Unirest.get("http://path_to_your_api/") .header("authorization", "Bearer ")
				 * .asString();
				 */
				
			}
			else{
				logger.debug("Could not generate Access token for client_credentials grant_type");
			}
		}
		
		else {
			//Access protected resource from server using OAuth2.0
			// Response from the resource server must be in Json or Urlencoded or xml
			logger.debug("Resource endpoint url: " + oauthDetails.getResourceServerUrl());
			logger.debug("Attempting to retrieve protected resource");
			OAuthUtils.getProtectedResource(oauthDetails);
		}
		return accessToken;
	}
}
