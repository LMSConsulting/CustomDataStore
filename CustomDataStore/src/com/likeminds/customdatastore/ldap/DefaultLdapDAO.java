package com.likeminds.customdatastore.ldap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sourceid.saml20.domain.LdapDataSource;

public class DefaultLdapDAO
 {
  private final Logger logger = LoggerFactory.getLogger(DefaultLdapDAO.class);
  DefaultDirContextFactory dirContextFactory;
  
  public DefaultLdapDAO(DefaultDirContextFactory dirContextFactory)
  {
	  this.dirContextFactory = dirContextFactory;
  }

   
   public List<LdapRecord> search(LdapDataSource connFields, String filter, String ldapSearchBase, int ldapSearchScope, int ldapCountLimit, String... attributeIds) 
		   throws NamingException
   {
     DirContext dirContext = null;
     NamingEnumeration<SearchResult> results = null;
     try    {
       dirContext = dirContextFactory.make(connFields);
       
       SearchControls searchControls = new SearchControls();
       searchControls.setSearchScope(ldapSearchScope);
       searchControls.setCountLimit(ldapCountLimit);
       searchControls.setReturningAttributes(attributeIds);
       
       results = dirContext.search(ldapSearchBase, filter, searchControls);
     }    catch (CommunicationException e)
     {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    catch (ServiceUnavailableException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     } finally    {
       closeQuietly(dirContext);
 
     }
     List<LdapRecord> returnedRecords = new ArrayList();
       while (results.hasMoreElements())      {
         SearchResult searchResult = (SearchResult)results.next();
         Attributes attributes = searchResult.getAttributes();
         NamingEnumeration<? extends Attribute> attributeRecord = attributes.getAll();
         Map<String, List<String>> searchRecordAttributes = new HashMap();
         while (attributeRecord.hasMoreElements())        {
           Attribute attr = (Attribute)attributeRecord.next();
           String key = attr.getID();
           
           List<String> values = new ArrayList();
           NamingEnumeration<?> multivalue = attr.getAll();
           while (multivalue.hasMoreElements())          {
             Object singleValue = multivalue.next();
             String stringValue = singleValue != null ? singleValue.toString() : null;
             if (stringValue != null) {
               values.add(stringValue);
             }
           }
           multivalue.close();
 
           if ((key != null) && (values != null) && (!values.isEmpty())) {
             searchRecordAttributes.put(key, values);
           }
         }
         String dn = searchResult.getNameInNamespace();
         LdapRecord lr = new LdapRecord(dn, searchRecordAttributes);
         returnedRecords.add(lr);
       }    
     
     return returnedRecords;
   }
 
   public List<LdapRecord> search(LdapDataSource connFields, String filter, String ldapSearchBase, int ldapSearchScope, int ldapCountLimit)
     throws NamingException
   {
     String[] attrIds = null;
     return search(connFields, filter, ldapSearchBase, ldapSearchScope, ldapCountLimit, attrIds);
   }
 
 
 
   public LdapRecord get(LdapDataSource connFields, String distinguishedName, String... attributeIds)
     throws NamingException
   {
     DirContext dc = null;
     try    {
       dc = dirContextFactory.make(connFields);
       Attributes attributes = dc.getAttributes(distinguishedName, attributeIds);
       NamingEnumeration<? extends Attribute> attributeRecord = attributes.getAll();
       Map<String, List<String>> recordAttributes = new HashMap();      Attribute attr;
       while (attributeRecord.hasMoreElements())      {
         attr = (Attribute)attributeRecord.next();
         String key = attr.getID();
         
         List<String> values = new ArrayList();
         NamingEnumeration<?> multivalue = attr.getAll();
         while (multivalue.hasMoreElements())        {
           Object singleValue = multivalue.next();
           String stringValue = singleValue != null ? singleValue.toString() : null;
           if (stringValue != null) {
             values.add(stringValue);
           }
         }
         multivalue.close();
 
         if ((key != null) && (values != null) && (!values.isEmpty())) {
           recordAttributes.put(key, values);
         }
       }
       return new LdapRecord(distinguishedName, recordAttributes);
     }    catch (CommunicationException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    catch (ServiceUnavailableException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    catch (NameNotFoundException e)
     {
       throw new NamingException(String.format("No record found with name \"%s\"", new Object[] { distinguishedName }));
     }    finally
     {
       closeQuietly(dc);
     }
   }
 
   public LdapRecord get(LdapDataSource connFields, String distinguishedName)
     throws NamingException
   {
     String[] attrIds = null;
     return get(connFields, distinguishedName, attrIds);
   }
 
   public void update(LdapDataSource connFields, String distinguishedName, Attributes attributes)
     throws NamingException
   {
     DirContext dc = null;
     try    {
       dc = dirContextFactory.make(connFields);
       
       dc.modifyAttributes(distinguishedName, 2, attributes);
     }    catch (CommunicationException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    catch (ServiceUnavailableException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    catch (NameNotFoundException e)
     {
       throw new NamingException(String.format("No record found with name \"%s\"", new Object[] { distinguishedName }));
     }  finally
     {
       closeQuietly(dc);
     }
   }
 
 
   public void create(LdapDataSource connFields, String distinguishedName, Attributes attributes)
     throws NamingException
   {
     DirContext dc = null;
     try    {
       dc = dirContextFactory.make(connFields);
       dc.createSubcontext(distinguishedName, attributes);
     }    catch (CommunicationException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    catch (ServiceUnavailableException e)    {
       throw new NamingException(String.format("There was a problem connecting to the data store at %s.", new Object[] {connFields
         .getServerUrl() }));
     }    finally
     {
       closeQuietly(dc);
     }
   }
 
   private void closeQuietly(DirContext dc)
   {
     if (dc != null) {
       try      {
         dc.close();
       }      catch (NamingException e)      {
         logger.warn("Unable to close connection to configured data store.", e);
       }
     }
   }
 }
