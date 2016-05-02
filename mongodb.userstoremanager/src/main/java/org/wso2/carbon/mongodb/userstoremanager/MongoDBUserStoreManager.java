package org.wso2.carbon.mongodb.userstoremanager;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.LogFactory;
import org.apache.juli.logging.Log;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.ProfileConfigurationManager;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.WriteConcern;



import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreConstants;
public class MongoDBUserStoreManager implements UserStoreManager {

	private int tenantId;
	private DBCollection collection;
	private org.apache.commons.logging.Log log = LogFactory.getLog(MongoDBUserStoreManager.class);
	public MongoDBUserStoreManager()
	{
		this.tenantId = -1234;
	}
	
	protected DB getDBConnection() throws UserStoreException
	{
		String host = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(0).getValue();
		Integer port = Integer.parseInt(MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(1).getValue());
		String userName = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(2).getValue();
		String password = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(3).getValue();
		List<ServerAddress> seeds = new ArrayList<ServerAddress>();
		seeds.add(new ServerAddress(host));
		char[] pass=password.toCharArray();
		List<MongoCredential> credentials = new ArrayList<MongoCredential>();
		credentials.add(
				MongoCredential.createScramSha1Credential(userName,"wso2_carbon_db", pass)
		);
		MongoClient mongoClient = new MongoClient(seeds, credentials);
		mongoClient.setWriteConcern(WriteConcern.JOURNALED);
		DB db = (DB) mongoClient.getDatabase("test");
		if(db == null)
		{
			throw new UserStoreException("Error While make Connection to DB");
		}
		else{
			return db;
		}
	}
	public void addRememberMe(String arg0, String arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void addRole(String arg0, String[] arg1, Permission[] arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void addRole(String arg0, String[] arg1, Permission[] arg2, boolean arg3)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void addUser(String arg0, Object arg1, String[] arg2, Map<String, String> arg3, String arg4)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void addUser(String arg0, Object arg1, String[] arg2, Map<String, String> arg3, String arg4, boolean arg5)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public boolean authenticate(String arg0, Object arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public void deleteRole(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void deleteUser(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void deleteUserClaimValue(String arg0, String arg1, String arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void deleteUserClaimValues(String arg0, String[] arg1, String arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public String[] getAllProfileNames() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		DB db= getDBConnection();
		String[] profileNames=null;
		log.info("DB Connection Made Successfully");
		collection = db.getCollection("UM_USER_ATTRIBUTE");
		DBObject objet = new BasicDBObject("UM_TENANT_ID",tenantId);
		List list = collection.distinct("UM_PROFILE_ID", objet);
		if(!list.isEmpty())
		{
			for(int i=0;i<list.size();i++)
			{
				profileNames[i]=list.get(i).toString();
			}
			return extracted(profileNames);
		}
		else{
				
			throw new UserStoreException("User Profile is Empty");
		}
	}

	private String[] extracted(String[] profileNames) throws UserStoreException {
		if(profileNames == null)
		{
			throw new UserStoreException("No Any Profile found!");
			
		}
		return profileNames;
	}
	public org.wso2.carbon.user.api.ClaimManager getClaimManager() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public Properties getDefaultUserStoreProperties() {
		// TODO Auto-generated method stub
		Property[] mandotaryProperties = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.toArray(
				new Property[MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.size()]
				); 
		Property[] optionalProperties = MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.toArray(
				new Property[MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.size()]
				);
		Property[] advancedProperties = MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.toArray(
				new Property[MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.size()]
				);
		Properties properties = new Properties();
		properties.setMandatoryProperties(mandotaryProperties);
		properties.setOptionalProperties(optionalProperties);
		properties.setAdvancedProperties(advancedProperties);
		return properties;
	}

	public String[] getHybridRoles() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public Date getPasswordExpirationTime(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public String[] getProfileNames(String userName) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		DB db=getDBConnection();
		String[] profileNames = null;
		log.info("retrieving Profile Names...");
		collection = db.getCollection("UM_USER_ATTRIBUTE");
		DBCollection collection2 = db.getCollection("UM_USER");
		DBObject object = new BasicDBObject("UM_USER_NAME",userName).append("UM_TENANT_ID", tenantId); 
		List list = collection2.distinct("UM_USER_ID",object);
		if(!list.isEmpty())
		{
			for(int i=0;i<list.size();i++)
			{
				object = new BasicDBObject("UM_USER_ID",list.get(i).toString()).append("UM_TENANT_ID", tenantId);
				List profiles = collection.distinct("UM_PROFILE_ID",object);
				if(!profiles.isEmpty())
				{
					for(int j=0;j<profiles.size();j++)
					{
						profileNames[j] = profiles.get(j).toString();
					}
				}
			}
			return extracted(profileNames);
		}
		else{
			
			throw new UserStoreException("User not exsists");
		}
	}

	public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return tenant.getRealmConfig().getRealmProperties();
	}

	public String[] getRoleListOfUser(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public String[] getRoleNames() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public int getTenantId() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return this.tenantId;
	}

	public int getTenantId(String userName) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		if(this.tenantId != 0)
		{
			throw new UserStoreException("Not Allowed to Perform this operation");
		}
		DB db = getDBConnection();
		collection = db.getCollection("UM_USER");
		DBObject object = new BasicDBObject("UM_USER_NAME", userName);
		Object tenants = collection.findOne(object).get("UM_TENANT_ID");
		if(tenants == null)
		{
			throw new UserStoreException("User Not Exsits...");
		}
		this.tenantId = Integer.parseInt(tenants.toString());
		return this.tenantId;
	}

	public String getUserClaimValue(String arg0, String arg1, String arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public Claim[] getUserClaimValues(String arg0, String arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public Map<String, String> getUserClaimValues(String arg0, String[] arg1, String arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public int getUserId(String userName) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		DB db = getDBConnection();
		collection = db.getCollection("UM_USER");
		DBObject object = new BasicDBObject("UM_USER_NAME",userName);
		Object user_id = collection.findOne(object).get("UM_ID");
		if(user_id == null)
		{
			throw new UserStoreException("User not exsists");
		}
		return Integer.parseInt(user_id.toString());
	}

	public String[] getUserListOfRole(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public boolean isExistingRole(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isExistingRole(String arg0, boolean arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isExistingUser(String arg0) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isMultipleProfilesAllowed() {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isReadOnly() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isSCIMEnabled() throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isValidRememberMeToken(String arg0, String arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return false;
	}

	public String[] listUsers(String arg0, int arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	public void setUserClaimValue(String arg0, String arg1, String arg2, String arg3)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void setUserClaimValues(String arg0, Map<String, String> arg1, String arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void updateCredential(String arg0, Object arg1, Object arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void updateCredentialByAdmin(String arg0, Object arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void updateRoleListOfUser(String arg0, String[] arg1, String[] arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void updateRoleName(String arg0, String arg1) throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	public void updateUserListOfRole(String arg0, String[] arg1, String[] arg2)
			throws org.wso2.carbon.user.api.UserStoreException {
		// TODO Auto-generated method stub
		
	}

	

}
