package com.likeminds.custdatastore;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
//import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.SimpleFieldList;
import org.sourceid.saml20.adapter.gui.AbstractSelectionFieldDescriptor.OptionValue;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.LdapDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.RadioGroupFieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.domain.LdapDataSource;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

import com.likeminds.custdatastore.clients.Base64Encoded;
import com.likeminds.custdatastore.clients.OAuth2Client;
import com.likeminds.custdatastore.clients.OAuth3Client;
import com.likeminds.custdatastore.clients.OAuthConstants;
import com.likeminds.custdatastore.clients.OAuthUtils;
import com.likeminds.custdatastore.ldap.DefaultDirContextFactory;
import com.likeminds.custdatastore.ldap.DefaultLdapDAO;
//import com.pingidentity.admin.api.model.plugin.SelectFieldDescriptor;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sources.CustomDataSourceDriver;
import com.pingidentity.sources.CustomDataSourceDriverDescriptor;
import com.pingidentity.sources.SourceDescriptor;
import com.pingidentity.sources.gui.FilterFieldsGuiDescriptor;


public class CustDataStore implements CustomDataSourceDriver
{
	private static final String DATA_SOURCE_NAME = "Custom Data Store";
	private static final String DATA_SOURCE_CONFIG_DESC = "Configuration settings for the JSON data store";

    private static final String CONFIG_JSON_SOURCE_URL = "Rest API URL";
	private static final String CONFIG_JSON_SOURCE_FILE_FILENAME_DESC = "The Rest URL to fetch the Attribute";   
	
	
	private static final String SELECT_METHOD = "grant type";
	private static final String SELECT_METHOD_DESC = "Select any grant type";
	
	private static final String AUTHN_USER_NAME = "username";
	private static final String AUTHN_USER_NAME_DESC = "Username for basic authentication";
	
	private static final String AUTHN_USER_PASSWORD = "Password";
	private static final String AUTHN_USER_PASSWORD_DESC = "Password for basic authentication";
    
	private static final String CLIENT_ID = "client id";
	private static final String CLIENT_ID_DESC = "Enter the Client ID";
	
	private static final String CLIENT_SECRET = "client secret";
	private static final String CLIENT_SECRET_DESC = "Enter the client secret";
	
	private static final String AUTHENTICATION_SERVER_URL = "authentication server url";
	private static final String AUTHENTICATION_SERVER_DESC= "Please enter the authentication server URL";
	
    private static final String CONFIG_JSON_ID_ATTRIBUTE_NAME = "ID Attribute";
    private static final String CONFIG_JSON_ID_ATTRIBUTE_DESC = "Attribute to compare to the value provided in the filter.";
    
	/*
	 * private static final String STORE_NAME = "data store"; private static final
	 * String STORE_NAME_DESC = "Select your data store";
	 */
                                 
    private static final String CONFIG_JSON_ID_CASE_SENSITIVE_NAME = "Case Sensitive?";
    private static final String CONFIG_JSON_ID_CASE_SENSITIVE_DESC = "When comparing the ID attribute, should the test be case-sensitive.";

    private static final String CONFIG_FILTER_NAME = "Datastore filter";
    private static final String CONFIG_FILTER_DESC = "Value to compare to ID value.  (ie ${Username} for the username from the HTML adapter).";
    
    private static final String[] validRESTMethods = new String[] {"none", "basic", "client credentials", "ropc"};
    
    private static final String FIELD_LDAP_DATA_SOURCE = "LDAP Data source";
    private static final String FIELD_LDAP_QUERY_DIRECTORY = "Query Directory";
    private static final String FIELD_LDAP_BASE_DOMAIN = "Base Domain";
    private static final String FIELD_LDAP_SEARCH_FILTER = "Filter";
    private static final String FIELD_LDAP_SEARCH_SCOPE = "LDAP Search Scope";
    private static final String FIELD_LDAP_ATTRIBUTE_NAME = "LDAP Attribute Name";
    private static final String FIELD_LDAP_ATTRIBUTE_VALUE = "Attribute value";
    
    private static final String DESC_LDAP_DATA_SOURCE = "The LDAP data source used for looking up the Attribute";
    private static final String DESC_LDAP_QUERY_DIRECTORY = "Query directory for every time during Authentication";
    private static final String DESC_LDAP_BASE_DOMAIN = "The base domain for attribute retrieval.";
    private static final String DESC_LDAP_SEARCH_FILTER = "You may use ${username} as part of the query. Example (for Ping Directory): uid=${username}.)";
    private static final String DESC_LDAP_SEARCH_SCOPE = "OBJECT_SCOPE: limits the search to the base object. ONE_LEVEL_SCOPE: searches the immediate children of a base object, but excludes the base object itself. Default: SUBTREE_SCOPE: searches all child objects as well as the base object";
	private static final String DESC_LDAP_ATTRIBUTE_NAME ="Attribute name that controls rendering of Privacy Policy screen";
	private static final String DESC_LDAP_ATTRIBUTE_VALUE = "Attribute value to be considered as accepted";
    
    private LdapDataSource LDAP_DATA_SOURCE;
	private boolean ATTR_LDAP_QUERY_DIRECTORY;
	private String ATTR_LDAP_BASE_DOMAIN;
	private String ATTR_LDAP_SEARCH_FILTER;
	private int ATTR_LDAP_SEARCH_SCOPE;
	private String ATTR_LDAP_ATTRIBUTE_NAME;
	private String ATTR_LDAP_ATTRIBUTE_VALUE;
	
	private static final String DEFAULT_LDAP_SEARCH_SCOPE = "SUBTREE";
	private static final boolean DEFAULT_LDAP_QUERY_DIRECTORY = true;
	private static final String DEFAULT_LDAP_ATTRIBUTE_VALUE = "true";
	private static final String DEFAULT_LDAP_ATTRIBUTE_NAME = "privacypolicyflag";
    
    private Log log = LogFactory.getLog(this.getClass());
    private final CustomDataSourceDriverDescriptor descriptor;

    private String JsonURL;
    private String idAttribute;
    private Boolean caseSensitiveSearch;
    
    private static ArrayList<OptionValue> listScopes() {
		ArrayList<OptionValue> searchScopeList = new ArrayList<OptionValue>();
		searchScopeList.add(new OptionValue("OBJECT", "0"));
		searchScopeList.add(new OptionValue("ONE_LEVEL", "1"));
		searchScopeList.add(new OptionValue("SUBTREE", "2"));
		return searchScopeList;
	}
    
    private JSONParser parser = new JSONParser();
   

    public CustDataStore()
    {
    	
    	GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
		guiDescriptor.setDescription("REST Service Password Credential Validator");
        // create the configuration descriptor for our custom data store
        AdapterConfigurationGuiDescriptor dataStoreConfigGuiDesc = new AdapterConfigurationGuiDescriptor(DATA_SOURCE_CONFIG_DESC);

		TextFieldDescriptor sourceUrl = new TextFieldDescriptor(CONFIG_JSON_SOURCE_URL, CONFIG_JSON_SOURCE_FILE_FILENAME_DESC);
        dataStoreConfigGuiDesc.addField(sourceUrl);
        
        TextFieldDescriptor idAttribute = new TextFieldDescriptor(CONFIG_JSON_ID_ATTRIBUTE_NAME, CONFIG_JSON_ID_ATTRIBUTE_DESC); 
        dataStoreConfigGuiDesc.addField(idAttribute);
       		
        SelectFieldDescriptor restMethodDescriptor = new SelectFieldDescriptor(SELECT_METHOD, SELECT_METHOD_DESC, validRESTMethods);
        restMethodDescriptor.setDefaultValue("none");
        dataStoreConfigGuiDesc.addField(restMethodDescriptor);
		 
		        
        TextFieldDescriptor sourceAuthUserName = new TextFieldDescriptor(AUTHN_USER_NAME, AUTHN_USER_NAME_DESC);
        dataStoreConfigGuiDesc.addField(sourceAuthUserName);
        
        TextFieldDescriptor sourceAuthUserPwd = new TextFieldDescriptor(AUTHN_USER_PASSWORD, AUTHN_USER_PASSWORD_DESC);
        dataStoreConfigGuiDesc.addField(sourceAuthUserPwd);

        TextFieldDescriptor clientid = new TextFieldDescriptor(CLIENT_ID, CLIENT_ID_DESC);
        dataStoreConfigGuiDesc.addField(clientid);
        
        TextFieldDescriptor clientsecret = new TextFieldDescriptor(CLIENT_SECRET, CLIENT_SECRET_DESC);
        dataStoreConfigGuiDesc.addField(clientsecret);
        
        
        
        TextFieldDescriptor authserverurl = new TextFieldDescriptor(AUTHENTICATION_SERVER_URL, AUTHENTICATION_SERVER_DESC);
        dataStoreConfigGuiDesc.addField(authserverurl);
         
       
        CheckBoxFieldDescriptor idCaseSensitivity = new CheckBoxFieldDescriptor(CONFIG_JSON_ID_CASE_SENSITIVE_NAME, CONFIG_JSON_ID_CASE_SENSITIVE_DESC);
		idCaseSensitivity.setDefaultValue(false);
        dataStoreConfigGuiDesc.addAdvancedField(idCaseSensitivity);
       
        // Add the configuration field for the search Filter
        FilterFieldsGuiDescriptor filterFieldsDescriptor = new FilterFieldsGuiDescriptor();
        filterFieldsDescriptor.addField(new TextFieldDescriptor(CONFIG_FILTER_NAME, CONFIG_FILTER_DESC));
        //LDAP
        
        CheckBoxFieldDescriptor queryDirectoryField = new CheckBoxFieldDescriptor(
				FIELD_LDAP_QUERY_DIRECTORY, DESC_LDAP_QUERY_DIRECTORY);
		queryDirectoryField.setDefaultValue(DEFAULT_LDAP_QUERY_DIRECTORY);
		dataStoreConfigGuiDesc.addAdvancedField(queryDirectoryField);
		
		LdapDatastoreFieldDescriptor ds = new LdapDatastoreFieldDescriptor(FIELD_LDAP_DATA_SOURCE, DESC_LDAP_DATA_SOURCE);
        dataStoreConfigGuiDesc.addField(ds);
		TextFieldDescriptor baseDomainField = new TextFieldDescriptor(FIELD_LDAP_BASE_DOMAIN,DESC_LDAP_BASE_DOMAIN);
		dataStoreConfigGuiDesc.addAdvancedField(baseDomainField);
		
		TextFieldDescriptor ldapFilerField = new TextFieldDescriptor(FIELD_LDAP_SEARCH_FILTER,DESC_LDAP_SEARCH_FILTER);
		dataStoreConfigGuiDesc.addAdvancedField(ldapFilerField);
		
		RadioGroupFieldDescriptor searchScopeDescriptor = new RadioGroupFieldDescriptor(FIELD_LDAP_SEARCH_SCOPE, 
				DESC_LDAP_SEARCH_SCOPE,listScopes());
		searchScopeDescriptor.setDefaultValue(DEFAULT_LDAP_SEARCH_SCOPE);
		dataStoreConfigGuiDesc.addAdvancedField(searchScopeDescriptor);
		
        TextFieldDescriptor flagAttribute = new TextFieldDescriptor(FIELD_LDAP_ATTRIBUTE_NAME,DESC_LDAP_ATTRIBUTE_NAME);
        flagAttribute.setDefaultValue(DEFAULT_LDAP_ATTRIBUTE_NAME);
        dataStoreConfigGuiDesc.addAdvancedField(flagAttribute);
        
        TextFieldDescriptor flagValue = new TextFieldDescriptor(FIELD_LDAP_ATTRIBUTE_VALUE,DESC_LDAP_ATTRIBUTE_VALUE);
        flagValue.setDefaultValue(DEFAULT_LDAP_ATTRIBUTE_VALUE);
        dataStoreConfigGuiDesc.addAdvancedField(flagValue);
        
        descriptor = new CustomDataSourceDriverDescriptor(this, DATA_SOURCE_NAME, dataStoreConfigGuiDesc, filterFieldsDescriptor);
    }
    
    
	/*
	 * public static void main(String[] args) { try { CustDataStore.call_me(); }
	 * catch (Exception e) { e.printStackTrace(); } }
	 */
    private Configuration configuration = null;	
    private DefaultLdapDAO ldapDAO = null;
    private static String respEmail =  null;
    
    
	public static String restConnector(Configuration configuration) throws Exception {
		Properties config = OAuthUtils.getClientConfigProps(OAuthConstants.CONFIG_FILE_PATH);
	     String resource_url = (String) config.get(OAuthConstants.RESOURCE_SERVER_URL);
	     Base64Encoded encode = new Base64Encoded();
	     OAuth2Client client_creds = new OAuth2Client();
	     String none = null;
	     String basic_Auth = null;
	     String client_credentials_Accesstoken = null;
	     String ropc_Accessstoken = null;
	     String grant_type = configuration.getFieldValue(FIELD_LDAP_DATA_SOURCE); 
	     if(grant_type == "basic_auth")
	     {
	     basic_Auth = encode.encodeCredentials((String) config.get(OAuthConstants.CLIENT_ID), (String) config.get(OAuthConstants.CLIENT_SECRET));
	     }
	     else if(grant_type == "client_credentials")
	     {
	     client_credentials_Accesstoken = OAuth2Client.OauthClient();
	     }
	     else if(grant_type == "rpoc")
	     {
	     ropc_Accessstoken = OAuth3Client.getResourceCredentials((String) config.get(OAuthConstants.USERNAME), (String) config.get(OAuthConstants.PASSWORD));
	     }
	   //opening connection
	     URL obj = new URL(resource_url);	     
	     HttpURLConnection con = (HttpURLConnection) obj.openConnection();
	     con.setReadTimeout(1000);
	     //Basic Auth
	     if(grant_type == "basic_auth")
	     {
	     con.setRequestProperty("Authorization", "Basic " + basic_Auth);
	     }
	     //Client credentials
	     else if(grant_type == "client_credentials")
	     {
	     con.setRequestProperty("Authorization", "Bearer " + client_credentials_Accesstoken);
	     }
	     //ROPC
	     else if(grant_type == "rpoc")
	     {
	     con.setRequestProperty("Authorization", "Bearer " + ropc_Accessstoken);
	     }
	     // optional default is GET
	     con.setRequestMethod("GET");
	     //add request header
	     con.setRequestProperty("User-Agent", "Mozilla/5.0");
	     int responseCode = con.getResponseCode();
	     System.out.println("Response Code : " + responseCode);
	     BufferedReader in = new BufferedReader(
	     new InputStreamReader((InputStream) con.getContent()));
	     String inputLine;
	     StringBuffer response = new StringBuffer();
	     while ((inputLine = in.readLine()) != null) {
	     	response.append(inputLine);
	     }
	     in.close();
	     //print in String
	     System.out.println(response.toString());
	     //Read JSON response and print
	     JSONObject Response = new JSONObject(response.toString());
	     System.out.println("::::::::::::"+  Response);
	     respEmail = Response.getString("userName");
	     System.out.println("Response Attribute "+Response.getString("userName"));
	     return respEmail;
	     
	   }


	@Override
	public SourceDescriptor getSourceDescriptor() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public void configure(Configuration config) {
		 this.configuration = config;
	        ATTR_LDAP_QUERY_DIRECTORY= configuration.getAdvancedFields().getBooleanFieldValue(FIELD_LDAP_QUERY_DIRECTORY);
			if(ATTR_LDAP_QUERY_DIRECTORY) {
				String ATTR_LDAP_DATA_SOURCE = configuration.getAdvancedFields().getFieldValue(FIELD_LDAP_DATA_SOURCE);
				LDAP_DATA_SOURCE = MgmtFactory.getDataSourceManager().getLdapDataSource(ATTR_LDAP_DATA_SOURCE);
				ATTR_LDAP_QUERY_DIRECTORY = configuration.getAdvancedFields().getBooleanFieldValue(FIELD_LDAP_QUERY_DIRECTORY);
				ATTR_LDAP_BASE_DOMAIN = configuration.getAdvancedFields().getFieldValue(FIELD_LDAP_BASE_DOMAIN);
				ATTR_LDAP_SEARCH_FILTER =configuration.getAdvancedFields().getFieldValue(FIELD_LDAP_SEARCH_FILTER);
				ATTR_LDAP_SEARCH_SCOPE =  Integer.valueOf(configuration.getAdvancedFields().getFieldValue(FIELD_LDAP_SEARCH_SCOPE));
				ATTR_LDAP_ATTRIBUTE_NAME = configuration.getAdvancedFields().getFieldValue(FIELD_LDAP_ATTRIBUTE_NAME);
				ATTR_LDAP_ATTRIBUTE_VALUE = configuration.getAdvancedFields().getFieldValue(FIELD_LDAP_ATTRIBUTE_VALUE);
				ldapDAO = new DefaultLdapDAO(new DefaultDirContextFactory());
			}
		
	}


	@Override
	public boolean testConnection() {
		// TODO Auto-generated method stub
		return false;
	}


	@Override
	public Map<String, Object> retrieveValues(Collection<String> var1, SimpleFieldList var2) {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public List<String> getAvailableFields() {
		// TODO Auto-generated method stub
		return null;
	}
	

}
