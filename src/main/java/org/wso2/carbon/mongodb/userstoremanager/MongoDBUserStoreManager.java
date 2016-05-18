package org.wso2.carbon.mongodb.userstoremanager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.axiom.om.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.LogFactory;
import org.apache.juli.logging.Log;
import org.bson.Document;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.ProfileConfigurationManager;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.common.UserRolesCache;
import org.wso2.carbon.user.core.hybrid.HybridRoleManager;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.MongoException;
import com.mongodb.MongoWriteException;
import com.mongodb.ServerAddress;
import com.mongodb.WriteConcern;
import com.mongodb.WriteResult;

import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.mongodb.util.MongoDBRealmUtil;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.mongodb.query.MongoQueryException;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreConstants;
public class MongoDBUserStoreManager implements UserStoreManager {

	private int tenantId;
	private DB db;
	private DBCollection collection;
    protected RealmConfiguration realmConfig = null;
    protected ClaimManager claimManager = null;
    protected ProfileConfigurationManager profileManager = null;
    protected UserRealm userRealm = null;
    protected HybridRoleManager hybridRoleManager = null;
    private boolean userRolesCacheEnabled = true;
    private String cacheIdentifier;
    private boolean replaceEscapeCharactersAtUserLogin = true;
    protected UserRolesCache userRolesCache = null;
    protected Random random = new Random();
    
	private org.apache.commons.logging.Log log = LogFactory.getLog(MongoDBUserStoreManager.class);

	public MongoDBUserStoreManager(){

		this.tenantId = -1234;
	}

	public MongoDBUserStoreManager(RealmConfiguration configuration)
	{
		this.tenantId = -1234;
		this.realmConfig = configuration;
		this.realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(this.realmConfig.getUserStoreProperties()));
		initUserRolesCache();
	}
	
	public MongoDBUserStoreManager(RealmConfiguration configuration,int tenantID)
	{
		this.realmConfig = configuration;
		this.tenantId = tenantID;
		realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig.getUserStoreProperties()));
		//initialize user role cache
		initUserRolesCache();
	}
	protected DB getDBConnection() throws UserStoreException
	{
		String host = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(0).getValue();
		String userName = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(2).getValue();
		String password = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.get(3).getValue();
		String database = MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.get(0).getValue();
		List<ServerAddress> seeds = new ArrayList<ServerAddress>();
		seeds.add(new ServerAddress(host));
		char[] pass=password.toCharArray();
		List<MongoCredential> credentials = new ArrayList<MongoCredential>();
		credentials.add(
				MongoCredential.createCredential(userName,"wso2_carbon_db", pass)
		);
		MongoClient mongoClient = new MongoClient(seeds, credentials);
		mongoClient.setWriteConcern(WriteConcern.JOURNALED);
		if(database != null && !database.equals(""))
		{
			db = mongoClient.getDB(database);
		}
		else{
			db = mongoClient.getDB("wso2_carbon_db");
		}
		if(db == null)
		{
			throw new UserStoreException("Error While make Connection to DB");
		}
		else{
			return db;
		}
	}
	public void addRememberMe(String userName, String token) throws org.wso2.carbon.user.api.UserStoreException {

		try{
			db=getDBConnection();
			collection = db.getCollection("UM_HYBRID_REMEMBER_ME");
			BasicDBObject dbObject = new BasicDBObject("UM_USER_NAME",userName).append("UM_TENANT_ID",this.tenantId);
			DBCursor cursor = collection.find(dbObject);
			if(cursor.hasNext()){
				DBObject res = cursor.next();
				Date createdTime = Calendar.getInstance().getTime();
				if(res.get("UM_COOKIE_VALUE").toString().length()> 0 && res!=null){
					collection.updateMulti(new BasicDBObject("UM_COOKIE_VALUE",token).append("UM_CREATED_TIME", createdTime),
							new BasicDBObject("$set",new BasicDBObject("UM_USER_NAME",userName)).append("UM_TENANT_ID",this.tenantId));
					log.info("Update remember configuration successfully");
				}else{	
					BasicDBObject document = new BasicDBObject("UM_ID",getCollectionSequence("UM_HYBRID_REMEMBER_ME"));
					document.append("UM_USER_NAME",userName);
					document.append("UM_COOKIE_VALUE",token);
					document.append("UM_CREATED_TIME",createdTime);
					document.append("UM_TENANT_ID",this.tenantId);
					collection.insert(document);
					log.info("Insert new remember configuration successfully");
				}
			}
		}
		catch(MongoException e){
			log.error("Error :"+e.getMessage());
		}
		catch(Exception e){
			log.error("Error :"+e.getMessage());
		}
	}

	public double getCollectionSequence(String COLLECTION_NAME)
	{
		double seq=0;
		try {
			db = getDBConnection();
			DBCollection collection = db.getCollection("COUNTERS");
			BasicDBObject dbObject =new BasicDBObject("_id",COLLECTION_NAME);
			DBCursor cursor = collection.find(dbObject);
			if (!cursor.hasNext()) {
				collection.insert(new BasicDBObject("_id", COLLECTION_NAME).append("seq", 1));
				seq = 1;
			} else {
				seq = Double.parseDouble(cursor.next().get("seq").toString());
				collection.update(new BasicDBObject("_id", COLLECTION_NAME), new BasicDBObject("$set", new BasicDBObject("seq", seq + 1)));
			}
		}catch(MongoWriteException e){
			
			log.error("Error :"+e.getError().getMessage());
		}catch(MongoException e){
		
			log.error("Error :"+e.getMessage());
		}catch (UserStoreException e) {
			log.error("Error occurred:"+e.getMessage());
		}
		return seq;
	}
	public void addRole(String roleName, String[] userList, Permission[] permissions)
			throws org.wso2.carbon.user.api.UserStoreException {

		//DB dbConnection = null;
		if(!roleNameValid(roleName)){
			throw new UserStoreException(
                    "Role name not valid. Role name must be a non null string with following format, " +
                        realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX));
		}
		if (isExistingRole(roleName)) {
            throw new UserStoreException(
                    "Role name: "+roleName+" in the system. Please pick another role name.");
        }
		if (isReadOnly()) {
            hybridRoleManager.addHybridRole(roleName, userList);
        }
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
		DBObject object = new BasicDBObject("UM_TENANT_ID",tenantId);
		List list = collection.distinct("UM_PROFILE_ID", object);
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
		Property[] mandatoryProperties = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.toArray(
				new Property[MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.size()]
				); 
		Property[] optionalProperties = MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.toArray(
				new Property[MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.size()]
				);
		Property[] advancedProperties = MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.toArray(
				new Property[MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.size()]
				);
		Properties properties = new Properties();
		properties.setMandatoryProperties(mandatoryProperties);
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
			for (Object aList : list) {
				object = new BasicDBObject("UM_USER_ID", aList.toString()).append("UM_TENANT_ID", tenantId);
				List profiles = collection.distinct("UM_PROFILE_ID", object);
				if (!profiles.isEmpty()) {
					for (int j = 0; j < profiles.size(); j++) {
						profileNames[j] = profiles.get(j).toString();
					}
				}
			}
			return extracted(profileNames);
		}
		else{
			
			throw new UserStoreException("User not exists");
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
			throw new UserStoreException("User not exists...");
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

	/**
	 * @param userName
	 * @return
	 * @throws org.wso2.carbon.user.api.UserStoreException
	 */
	public int getUserId(String userName) throws org.wso2.carbon.user.api.UserStoreException {
		DB db = getDBConnection();
		collection = db.getCollection("UM_USER");
		DBObject object = new BasicDBObject("UM_USER_NAME",userName);
		Object user_id = collection.findOne(object).get("UM_ID");
		if(user_id == null)
		{
			throw new UserStoreException("User not exists");
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

	protected void initUserRolesCache() {

        String userRolesCacheEnabledString = (realmConfig.getUserStoreProperty(
                UserCoreConstants.RealmConfig.PROPERTY_ROLES_CACHE_ENABLED));

        String userCoreCacheIdentifier = realmConfig.getUserStoreProperty(UserCoreConstants.
                RealmConfig.PROPERTY_USER_CORE_CACHE_IDENTIFIER);

        if (userCoreCacheIdentifier != null && userCoreCacheIdentifier.trim().length() > 0) {
            cacheIdentifier = userCoreCacheIdentifier;
        }

        if (userRolesCacheEnabledString != null && userRolesCacheEnabledString.equals("")) {
            userRolesCacheEnabled = Boolean.parseBoolean(userRolesCacheEnabledString);
            if (log.isDebugEnabled()) {
                log.debug("User Roles Cache is configured to:" + userRolesCacheEnabledString);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.info("User Roles Cache is not configured. Default value: " +
                         userRolesCacheEnabled + " is taken.");
            }
        }

        if (userRolesCacheEnabled) {
            userRolesCache = UserRolesCache.getInstance();
        }

    }

	private void addInitialData() throws UserStoreException {
        boolean isAdminRoleAdded = false;
        try{
        	if (!isExistingRole(realmConfig.getAdminRoleName())) {
        		this.addRole(realmConfig.getAdminRoleName(), null, null);
        		isAdminRoleAdded = true;
        	}

        	if (!isExistingRole(realmConfig.getEveryOneRoleName())) {
        		this.addRole(realmConfig.getEveryOneRoleName(), null, null);
        	}

        	String adminUserName = getAdminUser();
        	if (adminUserName != null) {
        		realmConfig.setAdminUserName(adminUserName);
        	} else {
        		if (!isExistingUser(realmConfig.getAdminUserName())) {
        			if ("true".equals(realmConfig
        					.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY))) {
        				log.error("Admin user name is not valid");
        				throw new UserStoreException("Admin user name is not valid");
        			}
        			// it is not required to notify to the listeners, just persist data.
        			this.persistUser(realmConfig.getAdminUserName(), realmConfig.getAdminPassword(),
        					null, null, null, false);
        		}
        	}

        	// use isUserInRole method
        	if (isAdminRoleAdded) {
        		this.updateRoleListOfUser(realmConfig.getAdminUserName(), null,
        				new String[] { realmConfig.getAdminRoleName() });
        	}

        	// anonymous user and role
        	if (!isExistingUser(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME) && !this.isReadOnly()) {
        		byte[] password = new byte[12];
        		random.nextBytes(password);
        		this.addUser(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME, Base64.encode(password),
        				null, null, null);

        	}
        	// if the realm is read only the role will be hybrid
        	if (!isExistingRole(CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME)) {
        		this.addRole(CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME,
        				new String[] { CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME }, null);
        	}
        }catch(org.wso2.carbon.user.api.UserStoreException e){
        	
        	log.error("Error :"+e.getMessage());
        }
    }
	
	public String getAdminUser() throws org.wso2.carbon.user.api.UserStoreException {
        String[] users = getUserListOfRole(this.realmConfig.getAdminRoleName());
        if (users != null && users.length > 0) {
            return users[0];
        }
        return null;
    }
	
	private void persistUser(String userName, Object credential, String[] roleList,
			Map<String, String> claims, String profileName,
			boolean requirePasswordChange) throws UserStoreException {
		if (!checkUserNameValid(userName)) {
			throw new UserStoreException(
					"User name not valid. User name must be a non null string with following format, " +
							realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX));

		}

		if (!checkUserPasswordValid(credential)) {
			throw new UserStoreException(
					"Credential not valid. Credential must be a non null string with following format, " +
							realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));

		}

		boolean isExisting = checkExistingUserName(userName);
		if (isExisting) {
			throw new UserStoreException("User name : " + userName
					+ " exists in the system. Please pick another user name");
		}

		DB dbConnection;
		String password = (String) credential;
		try {
			dbConnection = getDBConnection();
			String sqlStmt1 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER);

			String saltValue = null;

			if ("true".equals(realmConfig.getUserStoreProperties().get(
					MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
				byte[] bytes = new byte[16];
				random.nextBytes(bytes);
				saltValue = Base64.encode(bytes);
			}

			password = this.preparePassword(password, saltValue);

			// do all 4 possibilities
			if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue == null)) {
				this.updateUserValue(dbConnection, userName, password,
						"", requirePasswordChange, new Date(), tenantId);
			} else if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue != null)) {
				this.updateUserValue(dbConnection, userName, password,
						saltValue, requirePasswordChange, new Date(), tenantId);
			} else if (!sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)
					&& (saltValue == null)) {
				this.updateUserValue(dbConnection, userName, password,
						null, requirePasswordChange, new Date(),0);
			} else {
				this.updateUserValue(dbConnection, userName, password,
						null,requirePasswordChange, new Date(),0);
			}

			String[] roles;
			if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
				roles = new String[0];
			} else {
				if (roleList == null || roleList.length == 0) {
					roles = new String[] { this.realmConfig.getEveryOneRoleName() };
				} else {
					Arrays.sort(roleList);
					if (Arrays.binarySearch(roleList, realmConfig.getEveryOneRoleName()) < 0) {
						roles = new String[roleList.length + 1];
						int i;
						for (i = 0; i < roleList.length; i++) {
							roles[i] = roleList[i];
						}
						roles[i] = realmConfig.getEveryOneRoleName();
					} else {
						roles = roleList;
					}
				}
			}

			// add user to role.
			String sqlStmt2;
			sqlStmt2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER
					+ "-" +"MONGO_QUERY");
			if (sqlStmt2 == null) {
				sqlStmt2 = realmConfig
						.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
			}
			if (sqlStmt2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
				MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection,sqlStmt2,roles,tenantId, userName, tenantId, tenantId);
			} else {
				MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, sqlStmt2,roles,
						tenantId, userName);
			}


			if (claims != null) {
				// add the properties
				if (profileName == null) {
					profileName = UserCoreConstants.DEFAULT_PROFILE;
				}

				for (Map.Entry<String, String> entry : claims.entrySet()) {
					String claimURI = entry.getKey();
					String propName = claimManager.getAttributeName(claimURI);
					String propValue = entry.getValue();
					addProperty(dbConnection, userName, propName, propValue, profileName);
				}
			}
		} catch (Throwable e) {
			log.error(e.getMessage(), e);
			throw new UserStoreException(e.getMessage(), e);
		} 
	}
	protected boolean checkUserNameValid(String userName)
            throws UserStoreException {

        if (userName == null || CarbonConstants.REGISTRY_SYSTEM_USERNAME.equals(userName)) {
            return false;
        }

        userName = userName.trim();

        if (userName.length() < 1) {
            return false;
        }

        String regularExpression = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.
                PROPERTY_USER_NAME_JAVA_REG_EX);
        return regularExpression == null || regularExpression.equals("") || isFormatCorrect(regularExpression, userName);

    }

	private boolean isFormatCorrect(String regularExpression, String attribute) {

        Pattern p = Pattern.compile(regularExpression);
        Matcher m = p.matcher(attribute);
        return m.matches();

    }
	
	 protected boolean checkUserPasswordValid(Object credential)
	            throws UserStoreException {

	        if (credential == null) {
	            return false;
	        }

	        if (!(credential instanceof String)) {
	            throw new UserStoreException("Can handle only string type credentials");
	        }

	        String password = ((String) credential).trim();

	        if (password.length() < 1) {
	            return false;
	        }

	        String regularExpression = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.
	                PROPERTY_JAVA_REG_EX);
	        return regularExpression == null || isFormatCorrect(regularExpression, password);
	    }
	 
	 protected String preparePassword(String password, String saltValue) throws UserStoreException {
	        try {
	            String digestInput = password;
	            if (saltValue != null) {
	                digestInput = password + saltValue;
	            }
	            String digestFunction = realmConfig.getUserStoreProperties().get(
	                    MongoDBRealmConstants.DIGEST_FUNCTION);
	            if (digestFunction != null) {
	                MessageDigest dgst = MessageDigest.getInstance(digestFunction);
	                byte[] byteValue = dgst.digest(digestInput.getBytes());
	                password = Base64.encode(byteValue);
	            }
	            return password;
	        } catch (NoSuchAlgorithmException e) {
	            log.error(e.getMessage(), e);
	            throw new UserStoreException(e.getMessage(), e);
	        }
	 }
	 
	 protected boolean checkExistingUserName(String userName){
		 
		 boolean isExisting;
		 String isUnique = realmConfig
				 .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
		 if ("true".equals(isUnique) && !CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
			 BasicDBObject uniqueUser = new BasicDBObject("UM_USER_NAME",userName);
			 DBCursor cursor = collection.find(uniqueUser);
			 isExisting = cursor.hasNext();
			 if(log.isDebugEnabled()) {
				 log.debug("The username should be unique across tenants.");
			 }
		 } else {
			 BasicDBObject userSearch = new BasicDBObject("UM_USER_NAME",userName).append("UM_TENANT_ID",this.tenantId);
			 DBCursor cursor = collection.find(userSearch);
			 isExisting = cursor.hasNext();
			 
		 }
		 return isExisting;
	 }
	 
	 protected void updateUserValue(DB connection,String userName,String Password,String saultValue,
			 boolean requirePasswordChange,Date date,int tenantId){
		 
		 BasicDBObject dbObject = new BasicDBObject();
		 dbObject.append("UM_USER_PASSWORD", Password);
		 dbObject.append("UM_CHANGED_TIME",date);
		 dbObject.append("UM_REQUIRE_CHANGE",requirePasswordChange);
		 BasicDBObject updateQuery = new BasicDBObject("UM_USER_NAME",userName);
		 if((saultValue.equals("")||saultValue==null) && tenantId == 0)
		 {
			collection.update(updateQuery, dbObject); 
		 }else if((saultValue.equals("")||saultValue==null) && tenantId != 0){
			 dbObject.append("UM_TENANT_ID",tenantId);
			 collection.update(updateQuery,dbObject); 
		 }else if(saultValue.length()>0 && tenantId !=0){
			dbObject.append("UM_SALT_VALUE",saultValue);
			dbObject.append("UM_TENANT_ID",tenantId);
			collection.update(updateQuery,dbObject);
		 }
		 else{
			 dbObject.append("UM_SALT_VALUE",saultValue);
			 collection.update(updateQuery,dbObject); 
		 }
		 
	 }

	 
	 public void addProperty(DB dbConnection, String userName, String propertyName,
	            String value, String profileName) throws UserStoreException {
		 
	 }
	 protected boolean roleNameValid(String roleName) {
		 if (roleName == null) {
			 return false;
		 }

		 if (roleName.length() < 1) {
			 return false;
		 }

		 String regularExpression =
				 realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
		 if (regularExpression != null) {
			 if (!isFormatCorrect(regularExpression, roleName)) {
				 return false;
			 }
		 }

		 return true;
	 }
	
}
