package com.likeminds.custdatastore.clients;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.util.Base64;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
public class OAuth3Client {
	static Properties config = OAuthUtils.getClientConfigProps(OAuthConstants.CONFIG_FILE_PATH);
	private static final Pattern pat = Pattern.compile(".*\"access_token\"\\s*:\\s*\"([^\"]+)\".*");
	private static final String clientId = (String) config.get(OAuthConstants.CLIENT_ID);//clientId
	private static final String clientSecret = (String) config.get(OAuthConstants.CLIENT_SECRET);//client secret
	private static final String tokenUrl = (String) config.get(OAuthConstants.AUTHENTICATION_SERVER_URL);
	private static final String auth = clientId + ":" + clientSecret;
	private static final String authentication = Base64.getEncoder().encodeToString(auth.getBytes());
	//Username is netId for the person making the call and the password is there password
	
	public static String getResourceCredentials(String userName, String password) {
	    String content = "grant_type=password&username=" + userName + "&password=" + password;
	    BufferedReader reader = null;
	    HttpsURLConnection connection = null;
	    String returnValue = "";
	    try {
	        URL url = new URL(tokenUrl);
	        connection = (HttpsURLConnection) url.openConnection();
	        connection.setRequestMethod("POST");
	        connection.setDoOutput(true);
	        connection.setRequestProperty("Authorization", "Basic " + authentication);
	        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
	        connection.setRequestProperty("Accept", "application/json");
	        PrintStream os = new PrintStream(connection.getOutputStream());
	        os.print(content);
	        os.close();
	        reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
	        String line = null;
	        StringWriter out = new StringWriter(connection.getContentLength() > 0 ? connection.getContentLength() : 2048);
	        while ((line = reader.readLine()) != null) {
	            out.append(line);
	        }
	        String response = out.toString();
	        Matcher matcher = pat.matcher(response);
	        if (matcher.matches() && matcher.groupCount() > 0) {
	            returnValue = matcher.group(1);
	        }
	    } catch (Exception e) {
	        System.out.println("Error : " + e.getMessage());
	    } finally {
	        if (reader != null) {
	            try {
	                reader.close();
	            } catch (IOException e) {
	            }
	        }
	        connection.disconnect();
	    }
	    return returnValue;
	    
	   
	}
	
	  public static void main(String[] args) { 
		  OAuth3Client test = new OAuth3Client(); 
	  
	  test.getResourceCredentials((String) config.get(OAuthConstants.USERNAME), (String) config.get(OAuthConstants.PASSWORD));
	  }
	 
}
