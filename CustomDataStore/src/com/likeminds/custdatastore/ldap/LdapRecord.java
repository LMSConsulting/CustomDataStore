package com.likeminds.custdatastore.ldap;

import java.util.List;
import java.util.Map;

public class LdapRecord
{
  private String distinguishedName;
  private Map<String, List<String>> attributes;
  
  public LdapRecord(String distinguishedName, Map<String, List<String>> attributes)
  {
    this.distinguishedName = distinguishedName;
    this.attributes = attributes;
  }
  public String getDistinguishedName()
  {
    return distinguishedName;
  }
  public void setDistinguishedName(String distinguishedName)
  {
    this.distinguishedName = distinguishedName;
  }
  public Map<String, List<String>> getAttributes()
  {
    return attributes;
  }
  
  public  List<String> getAttribute(String AttributeName)
  {
    return attributes.get(AttributeName);
  }
  
  public void setAttributes(Map<String, List<String>> attributes)
  {
    this.attributes = attributes;
  }
}