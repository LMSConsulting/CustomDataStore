package com.likeminds.custdatastore.ldap;

import java.util.Properties;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.sourceid.saml20.domain.LdapDataSource;
 
public class DefaultDirContextFactory
{
   private static final String LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
   private static final String LDAP_CONNECT_POOL = "com.sun.jndi.ldap.connect.pool";

   public DirContext make(LdapDataSource connInfo)
    throws  NamingException
   {
     if (connInfo == null) {
       throw new NamingException("Unable to get Directory context for null LDAP Information");

    }
    Properties env = new Properties();
     env.put("java.naming.factory.initial", LDAP_CONTEXT_FACTORY);
     env.put(LDAP_CONNECT_POOL, Boolean.TRUE.toString());
     env.put("java.naming.provider.url", connInfo.getServerUrl());
     env.put("java.naming.security.authentication", connInfo.getAuthenticationMethod());
     env.put("java.naming.security.principal", connInfo.getPrincipal());
     env.put("java.naming.security.credentials", connInfo.getCredentials());
     return new InitialDirContext(env);
   }
}