package org.wso2.carbon.mongodb.userstoremanager;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.mongodb.*;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.json.JSONObject;
import org.osgi.service.useradmin.User;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.mongodb.hybrid.HybridMongoDBConstants;
import org.wso2.carbon.mongodb.hybrid.HybridMongoDBRoleManager;
import org.wso2.carbon.mongodb.query.*;
import org.wso2.carbon.mongodb.system.SystemMongoUserRoleManager;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.mongodb.util.MongoUserCoreUtil;
import org.wso2.carbon.user.core.*;
import org.wso2.carbon.user.core.authorization.AuthorizationCache;
import org.wso2.carbon.user.core.authorization.TreeNode;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.claim.ClaimMapping;
import org.wso2.carbon.user.core.common.*;
import org.wso2.carbon.user.core.dto.RoleDTO;
import org.wso2.carbon.user.core.hybrid.HybridRoleManager;
import org.wso2.carbon.user.core.internal.UMListenerServiceComponent;
import org.wso2.carbon.user.core.ldap.LDAPConstants;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.listener.UserStoreManagerConfigurationListener;
import org.wso2.carbon.user.core.listener.UserStoreManagerListener;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.jdbc.JDBCRoleContext;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.system.SystemUserRoleManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.mongodb.util.MongoDBRealmUtil;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.mongodb.query.MongoQueryException;

import javax.sql.DataSource;

public class MongoDBUserStoreManager implements UserStoreManager{


    protected static final String TRUE_VALUE = "true";
    protected static final String FALSE_VALUE = "false";
    private static final String MAX_LIST_LENGTH = "100";
    private static final String DISAPLAY_NAME_CLAIM = "http://wso2.org/claims/displayName";
    private static final String USERNAME_CLAIM_URI = "urn:scim:schemas:core:1.0:userName";
    private static final String APPLICATION_DOMAIN = "Application";
    private static final String WORKFLOW_DOMAIN = "Workflow";
    private static final String USER_NOT_FOUND = "UserNotFound";
    private static final String EXISTING_USER = "UserAlreadyExisting";
    private static final String INVALID_CLAIM_URL = "InvalidClaimUrl";
    private static final String INVALID_USER_NAME = "InvalidUserName";
    private static final String EXISTING_ROLE = "RoleExisting";
    private static final String READ_ONLY_STORE = "ReadOnlyUserStoreManager";
    private static final String READ_ONLY_PRIMARY_STORE = "ReadOnlyPrimaryUserStoreManager";
    private static final String INVALID_ROLE = "InvalidRole";
    private static final String ANONYMOUS_USER = "AnonymousUser";
    private static final String INVALID_OPERATION = "InvalidOperation";
    private static final String NO_READ_WRITE_PERMISSIONS = "NoReadWritePermission";
    private static final String SHARED_USER_ROLES = "SharedUserRoles";
    private static final String REMOVE_ADMIN_USER = "RemoveAdminUser";
    private static final String LOGGED_IN_USER = "LoggedInUser";
    private static final String ADMIN_USER = "AdminUser";
    private static final String INVALID_PASSWORD = "PasswordInvalid";
    private static final String PROPERTY_PASSWORD_ERROR_MSG = "PasswordJavaRegExViolationErrorMsg";
    protected RealmConfiguration realmConfig = null;
    protected ClaimManager claimManager = null;
    protected UserRealm userRealm = null;
    // User roles cache
    protected UserRolesCache userRolesCache = null;
    protected boolean readGroupsEnabled = false;
    protected boolean writeGroupsEnabled = false;
    private UserStoreManager secondaryUserStoreManager;
    private boolean userRolesCacheEnabled = true;
    private String cacheIdentifier;
    private boolean replaceEscapeCharactersAtUserLogin = true;
    private Map<String, UserStoreManager> userStoreManagerHolder = new HashMap<String, UserStoreManager>();
    private Map<String, Integer> maxUserListCount = null;
    private Map<String, Integer> maxRoleListCount = null;
    private List<UserStoreManagerConfigurationListener> listener = new ArrayList<UserStoreManagerConfigurationListener>();
	private int tenantId;
	private DB db;
	private DBCollection collection;
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    protected Random random = new Random();
    private static final String SHA_1_PRNG = "SHA1PRNG";
    protected HybridMongoDBRoleManager mongoDBRoleManager = null;
    protected SystemMongoUserRoleManager systemMongoUserRoleManager = null;
    protected SystemUserRoleManager systemUserRoleManager = null;
    protected HybridRoleManager hybridRoleManager = null;
    public static DataSource dataSource = null;
    private static final String MULIPLE_ATTRIBUTE_ENABLE = "MultipleAttributeEnable";
	private org.apache.commons.logging.Log log = LogFactory.getLog(MongoDBUserStoreManager.class);
    private static final ThreadLocal<Boolean> isSecureCall = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }
    };


	public MongoDBUserStoreManager(){

		//this.tenantId = -1234;
	}

    public MongoDBUserStoreManager(RealmConfiguration configuration,int tenantID) throws UserStoreException {
        this.realmConfig = configuration;
        this.tenantId = tenantID;
        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig.getUserStoreProperties()));
        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()){
                writeGroupsEnabled = true;
            }
        }

        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }
        //initialize user role cache
        initUserRolesCache();
    }

    public MongoDBUserStoreManager(DB ds,RealmConfiguration realmConfig,int tenantId,boolean addInitData) throws UserStoreException {

        this(realmConfig,tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig
                .getUserStoreProperties()));
        this.db = ds;
        if(ds==null){
            ds = MongoDatabaseUtil.getRealmDataSource(realmConfig);
        }
        if(ds==null){
            throw new UserStoreException("User Management Data Source is null");
        }
        doInitialSetup();
        this.persistDomain();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
    }

    public MongoDBUserStoreManager(DB ds,RealmConfiguration realmConfig) throws UserStoreException{

        this(realmConfig, MultitenantConstants.SUPER_TENANT_ID);
        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig
                .getUserStoreProperties()));
        this.db = ds;
    }

    public MongoDBUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                   ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm,
                                   Integer tenantId) throws UserStoreException{
        this(realmConfig, properties, claimManager, profileManager, realm, tenantId, false);

    }

    public MongoDBUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                   ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm,
                                   Integer tenantId, boolean skipInitData) throws UserStoreException{

        this(realmConfig, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.claimManager = claimManager;
        this.userRealm = realm;

        try {
            db = loadUserStoreSpacificDataSoruce();

            if (db == null) {
                db = (DB)properties.get(UserCoreConstants.DATA_SOURCE);
            }
            if (db == null) {
                db = MongoDatabaseUtil.getRealmDataSource(realmConfig);
                properties.put(UserCoreConstants.DATA_SOURCE,db);
            }

            if (log.isDebugEnabled()) {
                log.debug("The MongoDBDataSource being used by MongoDBUserStoreManager :: "
                        + db.hashCode());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()){
                log.debug("Loading JDBC datasource failed",e );
            }
        }

        properties.put(UserCoreConstants.DATA_SOURCE, db);

        this.db = db;

        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig
                .getUserStoreProperties()));

        this.persistDomain();
        doInitialSetup();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        initUserRolesCache();

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
		/* Initialize user roles cache as implemented in AbstractUserStoreManager */

    }

	protected Map<String, String> getUserPropertyValues(String userName, String[] propertyNames,
                                                        String profileName) throws UserStoreException {
		if(profileName == null){
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        MongoPreparedStatement prepStmt = null;
        String[] propertyNamesSorted = propertyNames.clone();
        Arrays.sort(propertyNamesSorted);
        Map<String, String> map = new HashMap<String, String>();
        DB db = loadUserStoreSpacificDataSoruce();
        try{
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROPS_FOR_PROFILE);
            prepStmt = new MongoPreparedStatementImpl(db,mongoQuery);
            prepStmt.setString("users.UM_USER_NAME",userName);
            prepStmt.setString("UM_PROFILE_NAME",profileName);
            if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){
                prepStmt.setInt("users.UM_TENANT_ID",tenantId);
                prepStmt.setInt("UM_TENANT_ID",tenantId);
            }
            AggregationOutput result = prepStmt.aggregate();
            Iterable<DBObject> ite = result.results();
            Iterator<DBObject> cursor = ite.iterator();
            while(cursor.hasNext()){

                DBObject object = cursor.next();
                String name = object.get("UM_ATTR_NAME").toString();
                String value = object.get("UM_ATTR_VALUE").toString();
                if(Arrays.binarySearch(propertyNamesSorted,name)<0){
                    continue;
                }
                map.put(name,value);
            }
        }catch(Exception e){

            throw new UserStoreException(e.getMessage(), e);
        }finally {
            prepStmt.close();
        }
        return map;
	}

	protected boolean doCheckExistingRole(String roleName) throws UserStoreException {
        RoleContext roleContext = createRoleContext(roleName);
		return isExistingMongoDBRole(roleContext);
	}

	protected RoleContext createRoleContext(String roleName) throws UserStoreException {
        JDBCRoleContext searchCtx = new JDBCRoleContext();
        String[] roleNameParts = roleName.split(UserCoreConstants.TENANT_DOMAIN_COMBINER);
        int tenantId = -1;
        if (roleNameParts.length > 1) {
            tenantId = Integer.parseInt(roleNameParts[1]);
            searchCtx.setTenantId(tenantId);
        } else {
            tenantId = this.tenantId;
            searchCtx.setTenantId(tenantId);
        }

        if (tenantId != this.tenantId) {
            searchCtx.setShared(true);
        }
        searchCtx.setRoleName(roleNameParts[0]);
        return searchCtx;
	}

    protected boolean isExistingMongoDBRole(RoleContext context) throws UserStoreException{

        boolean isExisting;
        String roleName = context.getRoleName();
        Map<String,Object> map = new HashMap<String, Object>();
        map.put("UM_ROLE_NAME",roleName);
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_IS_ROLE_EXISTING);
        if (mongoQuery == null) {
            throw new UserStoreException("The MongoDB Query statement for is role existing role null");
        }
        if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){

            map.put("UM_TENANT_ID",((JDBCRoleContext)context).getTenantId());
            isExisting = isValueExisting(mongoQuery,null,map);
        }else{
            isExisting = isValueExisting(mongoQuery, null, map);
        }
        return isExisting;
    }

    protected boolean isValueExisting(String mongoQuery, DB db, Map<String,Object> params) throws UserStoreException{

        boolean isExisting = false;
        boolean doClose = false;
        try{

            if(db==null){
                db = loadUserStoreSpacificDataSoruce();
                doClose = true;
            }
            if (MongoDatabaseUtil.getIntegerValueFromDatabase(db, mongoQuery, params) > -1) {
                isExisting = true;
            }
            return isExisting;
        }catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Using MongoQuery : " + mongoQuery);
            throw new UserStoreException(e.getMessage(), e);
        }
    }

	protected boolean doCheckExistingUser(String userName) throws UserStoreException {

        Map<String,Object> map = new HashMap<String, Object>();
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_IS_USER_EXISTING);
        if (mongoQuery == null) {
            throw new UserStoreException("The sql statement for is user existing null");
        }
        boolean isExisting = false;
        map.put("UM_USER_NAME",userName);
        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if ("true".equals(isUnique)
                && !CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
            String uniquenesMongo = realmConfig
                    .getUserStoreProperty(MongoDBRealmConstants.USER_NAME_UNIQUE);
            isExisting = isValueExisting(uniquenesMongo, null, map);
            if (log.isDebugEnabled()) {
                log.debug("The username should be unique across tenants.");
            }
        } else {
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID",tenantId);
                isExisting = isValueExisting(mongoQuery, null,map);
            } else {
                isExisting = isValueExisting(mongoQuery, null, map);
            }
        }
        return isExisting;
	}

	protected String[] getUserListFromProperties(String property, String value, String profileName) throws UserStoreException {

        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        MongoPreparedStatement prepStmt = null;
        String[] users = new String[0];
        List<String> list = new ArrayList<String>();
        try{

            db = loadUserStoreSpacificDataSoruce();
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_FOR_PROP);
            prepStmt = new MongoPreparedStatementImpl(db,mongoQuery);
            prepStmt.setString("UM_ATTR_NAME",property);
            prepStmt.setString("UM_ATTR_VALUE",value);
            prepStmt.setString("UM_PROFILE_ID",profileName);
            DBCursor cursor = prepStmt.find();
            while(cursor.hasNext()){

                String name = cursor.next().get("UM_USER_NAME").toString();
                list.add(name);
            }
            if (list.size() > 0) {
                users = list.toArray(new String[list.size()]);
            }
        }catch(Exception e){
            throw new UserStoreException(e.getMessage(), e);
        }finally {
            prepStmt.close();
        }
        return users;
	}

	protected boolean doAuthenticate(String userName, Object credential) throws UserStoreException {

        if (!checkUserNameValid(userName)) {
            return false;
        }

        if (!checkUserPasswordValid(credential)) {
            return false;
        }

        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
            log.error("Anonnymous user trying to login");
            return false;
        }
        String mongoQuery = null;
        String password = (String) credential;
        boolean isAuthed = false;
        MongoPreparedStatement prepStmt = null;
        try{
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.SELECT_USER);
            prepStmt = new MongoPreparedStatementImpl(db,mongoQuery);
            if(log.isDebugEnabled()){
                log.debug(mongoQuery);
            }
            prepStmt.setString("UM_USER_NAME",userName);
            if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){

                prepStmt.setInt("UM_TENANT_ID",tenantId);
            }
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()){

                String storedPassword = cursor.next().get("UM_USER_PASSWORD").toString();
                String saltValue = null;
                if ("true".equalsIgnoreCase(realmConfig
                        .getUserStoreProperty(MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue = cursor.next().get("UM_SALT_VALUE").toString();
                }

                boolean requireChange = Boolean.parseBoolean(cursor.next().get("UM_REQUIRE_CHANGE").toString());
                BSONTimestamp timestamp =(BSONTimestamp) cursor.next().get("UM_CHANGED_TIME");
                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();

                if (requireChange == true && (timestamp.getTime() < date.getTime())) {
                    isAuthed = false;
                } else {
                    password = this.preparePassword(password, saltValue);
                    if ((storedPassword != null) && (storedPassword.equals(password))) {
                        isAuthed = true;
                    }
                }
            }
        }catch(Exception ex){

            log.error("Using MongoDB Query : " + mongoQuery);
            throw new UserStoreException("Authentication Failure",ex);
        }finally {
            prepStmt.close();
        }
        if (log.isDebugEnabled()) {
            log.debug("User " + userName + " login attempt. Login success :: " + isAuthed);
        }
        return isAuthed;
	}

    private String preparePassword(String password, String saltValue) throws UserStoreException {

        try {
            String digestInput = password;
            if (saltValue != null) {
                digestInput = password + saltValue;
            }
            String digsestFunction = realmConfig.getUserStoreProperties().get(
                    MongoDBRealmConstants.DIGEST_FUNCTION);
            if (digsestFunction != null) {

                if (digsestFunction
                        .equals(UserCoreConstants.RealmConfig.PASSWORD_HASH_METHOD_PLAIN_TEXT)) {
                    return password;
                }

                MessageDigest dgst = MessageDigest.getInstance(digsestFunction);
                byte[] byteValue = dgst.digest(digestInput.getBytes());
                password = Base64.encode(byteValue);
            }
            return password;
        } catch (NoSuchAlgorithmException e) {
            throw new UserStoreException(e.getMessage(), e);
        }
    }

    protected void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profileName, boolean requirePasswordChange) throws UserStoreException {

        persistUser(userName, credential, roleList, claims, profileName, requirePasswordChange);
	}

	protected void doUpdateCredential(String userName, Object newCredential, Object oldCredential) throws UserStoreException {

        this.doUpdateCredentialByAdmin(userName, newCredential);
	}

	protected void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {

        String mongoQuery;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_USER_PASSWORD);
        MongoPreparedStatement prepStmt;
        Map<String,Object> map = new HashMap<String, Object>();
        String saltValue = null;
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for delete user claim value is null");
        }
        if ("true".equalsIgnoreCase(realmConfig.getUserStoreProperties().get(
                MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
            saltValue = generateSaltValue();
        }
        String password = this.preparePassword((String) newCredential, saltValue);
        if(!isCaseSensitiveUsername()){

            userName = userName.toLowerCase();
            password = password.toLowerCase();

        }
        map.put("UM_USER_NAME",userName);
        map.put("UM_USER_PASSWORD",password);

        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            map.put("UM_REQUIRE_CHANGE",false);
            map.put("UM_TENANT_ID",tenantId);
            map.put("UM_CHANGED_TIME",new Date());
            map.put("UM_SALT_VALUE","");
            updateStringValuesToDatabase(null, mongoQuery, map);
        } else if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue != null) {
            map.put("UM_REQUIRE_CHANGE",false);
            map.put("UM_TENANT_ID",tenantId);
            map.put("UM_CHANGED_TIME",new Date());
            map.put("UM_SALT_VALUE",saltValue);
            updateStringValuesToDatabase(null, mongoQuery,map);
        } else if (!mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            map.put("UM_REQUIRE_CHANGE",false);
            map.put("UM_CHANGED_TIME",new Date());
            map.put("UM_SALT_VALUE","");
            updateStringValuesToDatabase(null, mongoQuery, map);
        } else {

            map.put("UM_REQUIRE_CHANGE",false);
            map.put("UM_CHANGED_TIME",new Date());
            map.put("UM_SALT_VALUE",saltValue);
            updateStringValuesToDatabase(null, mongoQuery,map);
        }

	}

    private String generateSaltValue() {
        String saltValue = null;
        try {
            SecureRandom secureRandom = SecureRandom.getInstance(SHA_1_PRNG);
            byte[] bytes = new byte[16];
            //secureRandom is automatically seeded by calling nextBytes
            secureRandom.nextBytes(bytes);
            saltValue = Base64.encode(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA1PRNG algorithm could not be found.");
        }
        return saltValue;
    }

    private void updateStringValuesToDatabase(DB dbConnection, String mongoQuery,
                                              Map<String,Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try{

            if(dbConnection == null) {

                localConnection = true;
                dbConnection = loadUserStoreSpacificDataSoruce();
            }
            JSONObject jsonKeys = new JSONObject(mongoQuery);
            List<String> keys = MongoDatabaseUtil.getKeys(jsonKeys);
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            Iterator<String> searchKeys = keys.iterator();
            while(searchKeys.hasNext()){
                String key = searchKeys.next();
                if(!key.equals("collection") && !key.equals("projection") && !key.equals("$set")) {
                    for(Map.Entry<String,Object> entry : params.entrySet()) {

                        if(entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                throw new UserStoreException("Invalid data provided");
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            } else if (entry.getValue() instanceof Date) {
                                // Timestamp timestamp = new Timestamp(((Date) param).getTime());
                                // prepStmt.setTimestamp(i + 1, timestamp);
                                prepStmt.setTimeStamp(key, new BSONTimestamp((Integer) entry.getValue(), 1));
                            } else if (entry.getValue() instanceof Boolean) {
                                prepStmt.setBoolean(key, (Boolean) entry.getValue());
                            }
                        }
                    }
                }
            }
            List<String> queryList = new ArrayList<String>();
            queryList.add(mongoQuery);
            WriteResult result = MongoDatabaseUtil.updateTrue(queryList) ? prepStmt.update() : prepStmt.insert();
            if(!result.isUpdateOfExisting()){

                if(log.isDebugEnabled()){

                    log.debug("No documents were updated");
                }
            }else{

                if(log.isDebugEnabled()){

                    log.debug("Executed query is "+mongoQuery+" and number of updated documents ::"+result.getN());
                }
            }
        }catch(Exception e){

            String msg = "Error occurred while updating string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            if(localConnection){
                prepStmt.close();
            }
        }
    }

    private void deleteStringValuesFromDatabase(DB dbConnection, String mongoQuery,
                                                Object... params) throws  UserStoreException{

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try{

            if(dbConnection == null){

                localConnection = true;
                dbConnection = loadUserStoreSpacificDataSoruce();
            }
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoQuery);
            if (params != null && params.length > 0) {

                for (int i = 0; i < params.length; i++) {

                    Object param = params[i];
                    if (param == null) {

                        throw new UserStoreException("Invalid data provided");
                    }else if(param instanceof Integer){

                        if(i==0){

                            prepStmt.setInt("UM_ID",(Integer) param);
                        }else{

                            prepStmt.setInt("UM_TENANT_ID",(Integer) param);
                        }
                    }
                }
            }
            WriteResult result = prepStmt.update();
            if(!result.isUpdateOfExisting()){

                if(log.isDebugEnabled()){

                    log.debug("No documents were deleted");
                }
            }else{

                if(log.isDebugEnabled()){

                    log.debug("Executed query is "+mongoQuery+" and number of deleted documents ::"+result.getN());
                }
            }

        }catch(Exception ex){

            String msg = "Error occurred while deleting string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, ex);
            }
            throw new UserStoreException(msg, ex);
        }finally {
            if(localConnection){
                prepStmt.close();
            }
        }
    }

	protected void doDeleteUser(String userName) throws UserStoreException {

        String conditionQuery;
        int user_id=0;
        if(isCaseSensitiveUsername()) {

            userName = userName.toLowerCase();
        }
        conditionQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1);
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(db, conditionQuery);
        prepStmt.setString("UM_USER_NAME", userName);
        prepStmt.setInt("UM_TENANT_ID", tenantId);
        DB dbConnection = loadUserStoreSpacificDataSoruce();
        try {
            DBCursor cursor = prepStmt.find();
            user_id = Integer.parseInt(cursor.next().get("UM_ID").toString());
            if (user_id == 0) {

                log.warn("No registered usser found for given user name");
            } else {

                String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_USER_ROLE);
                String mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE);
                String mongoQuery3 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_USER);
                if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    this.deleteStringValuesFromDatabase(dbConnection, mongoQuery, userName, tenantId,
                            tenantId);
                    this.deleteStringValuesFromDatabase(dbConnection, mongoQuery2, userName, tenantId,
                            tenantId);
                    this.deleteStringValuesFromDatabase(dbConnection, mongoQuery3, userName, tenantId);
                }
            }
        } catch (MongoQueryException e) {
            e.printStackTrace();
        }

	}

	protected void doSetUserClaimValue(String userName, String claimURI, String claimValue,
                                       String profileName) throws UserStoreException {

        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        if (claimValue == null) {
            throw new UserStoreException("Cannot set null values.");
        }
        DB dbConnection=null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            String property = getClaimAtrribute(claimURI,userName,null);
            String value = getProperty(dbConnection,userName,property,profileName);
            if(value == null){
                addProperty(dbConnection,userName,property,claimValue,profileName);
            }
        }catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage =
                    "Error occurred while getting claim attribute for user : " + userName + " & claim URI : " +
                            claimURI;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }catch(Exception ex){

            String msg =
                    "Database error occurred while saving user claim value for user : " + userName + " & claim URI : " +
                            claimURI + " claim value : " + claimValue;
            if (log.isDebugEnabled()) {
                log.debug(msg, ex);
            }
            throw new UserStoreException(msg, ex);
        }
	}

    protected String getProperty(DB dbConnection, String userName, String property, String profileName) throws UserStoreException{

        MongoPreparedStatement prepStmt = null;
        try {
            String mongoQuery = null;
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROP_FOR_PROFILE);
            if (mongoQuery == null) {

                throw new UserStoreException("The mng statement for add user property mongo query is null");
            }
            String value = null;
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            prepStmt.setString("users.UM_USER_NAME", userName);
            prepStmt.setString("UM_PROFILE_ID", profileName);
            prepStmt.setString("UM_ATTR_NAME", property);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                prepStmt.setInt("UM_TENANT_ID", tenantId);
                prepStmt.setInt("users.UM_TENANT_ID", tenantId);
            }
            AggregationOutput cursor = prepStmt.aggregate();
            Iterable<DBObject> ite = cursor.results();
            Iterator<DBObject> iterator = ite.iterator();
            while(iterator.hasNext()){

                value = iterator.next().get("UM_ATTR_VALUE").toString();
            }
            return value;
        }catch(Exception e){

            String msg = "Error ocuured :";
            throw new UserStoreException(msg, e);
        }finally{
            prepStmt.close();
        }
    }

    protected void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName) throws UserStoreException {

        DB dbConnection = null;
        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        if (claims.get(UserCoreConstants.PROFILE_CONFIGURATION) == null) {
            claims.put(UserCoreConstants.PROFILE_CONFIGURATION,
                    UserCoreConstants.DEFAULT_PROFILE_CONFIGURATION);
        }
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            Iterator<Map.Entry<String,String>> ite = claims.entrySet().iterator();
            while(ite.hasNext()){

                Map.Entry<String,String> entry = ite.next();
                String claimUri = entry.getKey();
                String property = getClaimAtrribute(claimUri,userName,null);
                String value = entry.getValue();
                String exsistingValue = getProperty(dbConnection,userName,property,profileName);
                if(exsistingValue==null){
                    addProperty(dbConnection, userName, property, value, profileName);
                }else{
                    updateProperty(dbConnection, userName, property, value, profileName);
                }
            }
        }catch(org.wso2.carbon.user.api.UserStoreException e){

            String errorMessage = "Error occurred while getting claim attribute for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }catch(Exception e){

            String msg = "Database error occurred while setting user claim values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }

    }

    private void updateProperty(DB dbConnection, String userName, String property, String value, String profileName) throws UserStoreException, MongoQueryException {

        String mongoQuery=null;
        Map<String,Object> map = new HashMap<String, Object>();
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_USER_PROPERTY);
        if (mongoQuery == null) {

            throw new UserStoreException("The sql statement for add user property sql is null");
        }
        String conditionQuery = MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1;
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,conditionQuery);
        prepStmt.setString("UM_USER_NAME",userName);
        prepStmt.setInt("UM_TENANT_ID",tenantId);
        DBCursor cursor = prepStmt.find();
        if(cursor.hasNext()) {
            int userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            map.put("UM_USER_ID",userId);
            map.put("UM_ATTR_NAME",property);
            map.put("UM_PROFILE_ID",profileName);
            map.put("UM_ATTR_VALUE",value);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID",tenantId);
                updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {

                updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }
        }
    }

    protected void doDeleteUserClaimValue(String userName, String claimURI, String profileName) throws UserStoreException {

        DB dbConnection = null;
        if(profileName == null){

            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        try{

            String property = null;
            if (UserCoreConstants.PROFILE_CONFIGURATION.equals(claimURI)) {
                property = UserCoreConstants.PROFILE_CONFIGURATION;
            } else {
                property = getClaimAtrribute(claimURI, userName, null);
            }

            dbConnection = loadUserStoreSpacificDataSoruce();
            this.deleteProperty(dbConnection, userName, property, profileName);

        }catch(org.wso2.carbon.user.api.UserStoreException e){

            String errorMessage =
                    "Error occurred while getting claim attribute for user : " + userName + " & claim URI : " +
                            claimURI;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }catch(Exception e){

            String msg = "Database error occurred while deleting user claim value for user : " + userName +
                    " & claim URI : " + claimURI;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private void deleteProperty(DB dbConnection, String userName, String property, String profileName) throws UserStoreException, MongoQueryException {

        String mongoQuery = null;
        Map<String,Object> map = new HashMap<String, Object>();
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_USER_PROPERTY);
        String query = MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1;
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,query);
        prepStmt.setString("UM_USER_NAME",userName);
        prepStmt.setInt("UM_TENANT_ID",tenantId);
        DBCursor cursor = prepStmt.find();
        if(cursor.hasNext()) {

            int userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            map.put("UM_USER_ID",userId);
            map.put("UM_ATTR_NAME",property);
            map.put("UM_PROFILE_ID",profileName);
            if (mongoQuery == null) {

                throw new UserStoreException("The mongo statement for add user property mongo query is null");
            }
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID",tenantId);
                  updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {
                 updateStringValuesToDatabase(dbConnection, mongoQuery,map);
            }
        }
    }

    protected void doDeleteUserClaimValues(String userName, String[] claims, String profileName) throws UserStoreException {

        DB dbConnection = null;
        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            for (String claimURI : claims) {
                String property = getClaimAtrribute(claimURI, userName, null);
                this.deleteProperty(dbConnection, userName, property, profileName);
            }
        }catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage = "Error occurred while getting claim attribute for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }catch(Exception e) {
            String msg = "Database error occurred while deleting user claim values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally{
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
	}

	protected void doUpdateUserListOfRole(String roleName, String deletedUsers[], String[] newUsers) throws UserStoreException {

        JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(roleName);
        roleName = ctx.getRoleName();
        int roleTenantId = ctx.getTenantId();
        boolean isShared = ctx.isShared();
        String mongoQuery = null;
        mongoQuery = realmConfig.getUserStoreProperty(isShared ? MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE
            : MongoDBRealmConstants.REMOVE_USER_FROM_ROLE);
        if(mongoQuery==null){
            throw new UserStoreException("The mongo statement for remove user from role is null");
        }
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            Map<String,Object> map = new HashMap<String, Object>();
            if(isShared){

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
            }else{

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE);
            }
            if(mongoQuery == null){

                throw new UserStoreException("The mongo statement for add user to role is null");
            }
            int userIds[] = null;
            if(deletedUsers.length > 0)
            {
                userIds = getUserIDS(dbConnection,deletedUsers);
            }
            else{

                userIds = getUserIDS(dbConnection,newUsers);
            }

            String[] roles = {roleName};
            int roleIds[] = getRolesIDS(dbConnection, roles);
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY);
            Map<String, Object> mapRole = new HashMap<String, Object>();
            prepStmt.setString("UM_ROLE_NAME", roleName);
            mapRole.put("UM_USER_ID", userIds);
            if (isShared) {
                prepStmt.setInt("UM_TENANT_ID", roleTenantId);
                DBCursor cursor = prepStmt.find();
                if (cursor.hasNext()) {

                    roleIds[0] = Integer.parseInt(cursor.next().get("UM_ID").toString());
                    mapRole.put("UM_ROLE_ID", roleIds[0]);
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                            mapRole);
                }
            } else {
                if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    prepStmt.setInt("UM_TENANT_ID", roleTenantId);
                    DBCursor cursor = prepStmt.find();
                    if (cursor.hasNext()) {

                        roleIds[0] = Integer.parseInt(cursor.next().get("UM_ID").toString());
                        mapRole.put("UM_ROLE_ID", roleIds[0]);
                        mapRole.put("UM_TENANT_ID", tenantId);
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                mapRole);
                    }
                } else {
                    DBCursor cursor = prepStmt.find();
                    if (cursor.hasNext()) {

                        roleIds[0] = Integer.parseInt(cursor.next().get("UM_ID").toString());
                        mapRole.put("UM_ROLE_ID", roleIds[0]);
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                mapRole);
                    }
                }
            }
        }catch(Exception e){
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }

    }

	protected void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            String mongoQuery = null;
            String[] userNames = userName.split(CarbonConstants.DOMAIN_SEPARATOR);
            if (userNames.length > 1) {
                userName = userNames[1];
            }
            if (deletedRoles != null && deletedRoles.length > 0) {
                // if user name and role names are prefixed with domain name,
                // remove the domain name
                RoleBreakdown breakdown = getSharedRoleBreakdown(deletedRoles);
                String[] roles = breakdown.getRoles();

                // Integer[] tenantIds = breakdown.getTenantIds();

                String[] sharedRoles = breakdown.getSharedRoles();
                Integer[] sharedTenantIds = breakdown.getSharedTenantids();
                Map<String,Object> mapRole = new HashMap<String, Object>();
                if (roles.length > 0) {
                    mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.REMOVE_ROLE_FROM_USER);
                    if (mongoQuery == null) {
                        throw new UserStoreException(
                                "The mongo statement for remove user from role is null");
                    }
                    MongoPreparedStatement prepStmt2 = new MongoPreparedStatementImpl(dbConnection,MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY);
                    prepStmt2.setString("UM_USER_NAME",userName);
                    int rolesID[] = getRolesIDS(dbConnection,roles);
                    int userID = 0;
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        prepStmt.setInt("UM_TENANT_ID",tenantId);
                    }
                    DBCursor cursor = prepStmt.find();
                    userID = Integer.parseInt(cursor.next().get("UM_ID").toString());

                    mapRole.put("UM_USER_ID",userID);
                    mapRole.put("UM_ROLE_ID",rolesID);
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        mapRole.put("UM_TENANT_ID",tenantId);
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                mapRole);
                    } else {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery, mapRole);
                    }
                }

                if (sharedRoles.length > 0) {
                    mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE);

                    if (mongoQuery == null) {
                        throw new UserStoreException(
                                "The sql statement for remove user from role is null");
                    }

                    MongoDatabaseUtil.updateUserRoleMappingWithExactParams(dbConnection, mongoQuery,
                            sharedRoles, userName,
                            sharedTenantIds, tenantId);
                }
            }
            String mongoQuery2 = null;
            if (newRoles != null && newRoles.length > 0) {
                // if user name and role names are prefixed with domain name,
                // remove the domain name

                RoleBreakdown breakdown = getSharedRoleBreakdown(newRoles);
                String[] roles = breakdown.getRoles();
                // Integer[] tenantIds = breakdown.getTenantIds();

                String[] sharedRoles = breakdown.getSharedRoles();
                Integer[] sharedTenantIds = breakdown.getSharedTenantids();
                int roleIds[] = getRolesIDS(dbConnection,roles);
                String users[] = {userName};
                int userIds[] = getUserIDS(dbConnection,users);
                Map<String,Object> map = new HashMap<String, Object>();
                map.put("UM_ROLE_ID",roleIds);
                map.put("UM_USER_ID",userIds[0]);
                if (roles.length > 0) {

                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
                }
                if (mongoQuery2 == null) {

                    mongoQuery2 = MongoDBRealmConstants.ADD_ROLE_TO_USER;
                }
                if (mongoQuery2 == null) {
                    throw new UserStoreException(
                            "The mongo statement for add user to role is null");
                } else {

                    if(mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                        map.put("UM_TENANT_ID",tenantId);
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                                map);
                    }else{

                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, map);
                    }
                }


                if (sharedRoles.length > 0) {
                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
                    if (mongoQuery2 == null) {
                        throw new UserStoreException(
                                "The sql statement for remove user from role is null");
                    }

                    MongoDatabaseUtil.updateUserRoleMappingWithExactParams(dbConnection, mongoQuery2,
                            sharedRoles, userName,
                            sharedTenantIds, tenantId);

                }

            }

        }catch(Exception e){

            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private RoleBreakdown getSharedRoleBreakdown(String[] rolesList) throws UserStoreException {
        List<String> roles = new ArrayList<String>();
        List<Integer> tenantIds = new ArrayList<Integer>();

        List<String> sharedRoles = new ArrayList<String>();
        List<Integer> sharedTenantIds = new ArrayList<Integer>();

        for (String role : rolesList) {

            String[] deletedRoleNames = role.split(CarbonConstants.DOMAIN_SEPARATOR);
            if (deletedRoleNames.length > 1) {
                role = deletedRoleNames[1];
            }

            JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(role);
            role = ctx.getRoleName();
            int roleTenantId = ctx.getTenantId();
            boolean isShared = ctx.isShared();

            if (isShared) {
                sharedRoles.add(role);
                sharedTenantIds.add(roleTenantId);
            } else {
                roles.add(role);
                tenantIds.add(roleTenantId);
            }

        }

        RoleBreakdown breakdown = new RoleBreakdown();

        // Non shared roles and tenant ids
        breakdown.setRoles(roles.toArray(new String[roles.size()]));
        breakdown.setTenantIds(tenantIds.toArray(new Integer[tenantIds.size()]));

        // Shared roles and tenant ids
        breakdown.setSharedRoles(sharedRoles.toArray(new String[sharedRoles.size()]));
        breakdown.setSharedTenantids(sharedTenantIds.toArray(new Integer[sharedTenantIds.size()]));

        return breakdown;

    }

	protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException{

        if (log.isDebugEnabled()) {
            log.debug("Getting roles of user: " + userName + " with filter: " + filter);
        }
        String mongoQuery = null;
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(this.db,MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY);
        prepStmt.setString("UM_USER_NAME",userName);
        if(MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY.contains(UserCoreConstants.UM_TENANT_COLUMN)){

            prepStmt.setInt("UM_TENANT_ID",tenantId);
        }
        try {
            DBCursor cursor = prepStmt.find();
            int userId = 0;
            if (cursor.hasNext()) {

                userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            }

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USER_ROLE);
            List<String> roles = new ArrayList<String>();
            String[] names;
            if (mongoQuery == null) {
                throw new UserStoreException("The mongo statement for retrieving user roles is null");
            }
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("users.UM_ID", userId);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("userRole.UM_TENANT_ID", tenantId);
                map.put("users.UM_TENANT_ID", tenantId);
                map.put("UM_TENANT_ID", tenantId);
                names = getStringValuesFromDatabase(mongoQuery, map, true, true);
            } else {
                names = getStringValuesFromDatabase(mongoQuery, map, true, true);
            }
            if (log.isDebugEnabled()) {
                if (names != null) {
                    for (String name : names) {
                        log.debug("Found role: " + name);
                    }
                } else {
                    log.debug("No external role found for the user: " + userName);
                }
            }
            Collections.addAll(roles, names);
            return roles.toArray(new String[roles.size()]);
        }catch(MongoQueryException e){

            String msg = "Error occurred while retrieving user roles.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }
	}

    private String[] getStringValuesFromDatabase(String mongoQuery, Map<String,Object> params,boolean findStatus,boolean multipleLookUps)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + mongoQuery);
            for (int i = 0; i < params.size(); i++) {
                Object param = params.get(i);
                log.debug("Input value: " + param);
            }
        }

        String[] values = new String[0];
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            values = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection,mongoQuery,params,findStatus,multipleLookUps);
        }catch(Exception e){

            String msg = "Error occurred while retrieving string values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return values;
    }

    private String[] getDistinctStringValues(String mongoQuery, Map<String,Object> params) throws UserStoreException{

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + mongoQuery);
            for (int i = 0; i < params.size(); i++) {
                Object param = params.get(i);
                log.debug("Input value: " + param);
            }
        }

        String[] values = new String[0];
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            values = MongoDatabaseUtil.getDistinctStringValuesFromDatabase(dbConnection,mongoQuery,params);
        }catch(Exception e){

            String msg = "Error occurred while retrieving string values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return values;
    }

	protected String[] doGetSharedRoleListOfUser(String userName,
                                                 String tenantDomain, String filter) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Looking for shared roles for user: " + userName + " for tenant: " + tenantDomain);
        }
        if (isSharedGroupEnabled()) {
            // shared roles
            String mongoQuery = null;

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_SHARED_ROLES_FOR_USER);

            String[] sharedNames = getRoleNamesWithDomain(mongoQuery, userName, tenantId, true);

            return sharedNames;
        }
        return new String[0];
	}

    private String[] getRoleNamesWithDomain(String mongoQuery, String userName, int tenantId,
                                            boolean appendDn) throws UserStoreException{

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        List<String> roles = new ArrayList<String>();
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoQuery);
            byte count = 0;
            prepStmt.setString("UM_USER_NAME",userName);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            DBCursor cursor = prepStmt.find();
            String domain =
                    realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            while(cursor.hasNext()){

                String name = cursor.next().get("UM_ROLE_NAME").toString();
                int tenant = Integer.parseInt(cursor.next().get("UM_TENANT_ID").toString());
                String role = name;
                if (appendDn) {
                    name = UserCoreUtil.addTenantDomainToEntry(name, String.valueOf(tenant));
                }
                roles.add(role);
            }
        }catch(Exception e){

            String msg =
                    "Error occurred while retrieving role name with tenant id : " + tenantId + " & user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return roles.toArray(new String[roles.size()]);
    }

    protected void doAddRole(String roleName, String[] userList, boolean shared) throws UserStoreException {

        Map<String,Object> map = new HashMap<String, Object>();
        if (shared && isSharedGroupEnabled()) {
            doAddSharedRole(roleName, userList);
        }
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            int[] userId = new int[userList.length];
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE);
            map.put("UM_ROLE_NAME",roleName);
            int roleId = MongoDatabaseUtil.getIncrementedSequence(dbConnection,"UM_ROLE");
            map.put("UM_ID",roleId);
            map.put("UM_SHARED_ROLE",0);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID",tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }
            if (userList != null) {

                String mongoQuery2 = null;
                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY);
                if (mongoQuery2 == null) {
                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE);
                }
                MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(this.db,MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1);
                if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    String mongoCondition = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
                    MongoPreparedStatement prepStmt2 = new MongoPreparedStatementImpl(dbConnection,mongoCondition);
                    int roleID = -1;
                    prepStmt2.setString("UM_ROLE_NAME",roleName);
                    prepStmt2.setInt("UM_TENANT_ID",tenantId);
                    DBCursor cursor = prepStmt2.find();
                    roleID = Integer.parseInt(cursor.next().get("UM_ID").toString());
                    int[] userID = getUserIDS(dbConnection,userList);
                    Map<String,Object> mapRole = new HashMap<String, Object>();
                    mapRole.put("UM_USER_ID",userID);
                    mapRole.put("UM_ROLE_ID",roleId);
                    mapRole.put("UM_TENANT_ID",tenantId);
                    if(userId.length!=0) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                                mapRole);
                    }
                }else {

                    String mongoCondition = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
                    MongoPreparedStatement prepStmt2 = new MongoPreparedStatementImpl(dbConnection,mongoCondition);
                    int roleID = -1;
                    prepStmt2.setString("UM_ROLE_NAME",roleName);
                    DBCursor cursor = prepStmt.find();
                    roleID = Integer.parseInt(cursor.next().get("UM_ID").toString());
                    int[] userID = getUserIDS(dbConnection,userList);
                    Map<String,Object> mapRole = new HashMap<String, Object>();
                    mapRole.put("UM_USER_ID",roleID);
                    mapRole.put("UM_ROLE_ID",userID);
                    if(userId.length!=0) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, mapRole);
                    }
                }

            }
        }catch(Exception e){

            String msg = "Error occurred while adding role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private void doAddSharedRole(String roleName, String[] userList) throws UserStoreException{

        DB dbConnection = null;
        Map<String,Object> map = new HashMap<String, Object>();
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE);
            map.put("UM_ROLE_NAME",roleName);
            map.put("UM_SHARED_ROLE",roleName);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID",tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }

            if (userList != null) {

                String mongoQuery2 = null;
                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
                String mongoCondition = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
                MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoCondition);
                int roleID = -1;
                prepStmt.setString("UM_ROLE_NAME",roleName);
                if (mongoCondition.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    prepStmt.setInt("UM_TENANT_ID",tenantId);
                    DBCursor cursor = prepStmt.find();
                    roleID = Integer.parseInt(cursor.next().get("UM_ID").toString());
                } else {
                    DBCursor cursor = prepStmt.find();
                    roleID = Integer.parseInt(cursor.next().get("UM_ID").toString());
                }
                int[] userID = getUserIDS(dbConnection,userList);
                Map<String,Object> mapRole = new HashMap<String, Object>();
                mapRole.put("UM_USER_ID",roleID);
                mapRole.put("UM_ROLE_ID",userID);
                if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    mapRole.put("UM_TENANT_ID",tenantId);
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                            mapRole);
                }else {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, mapRole);
                }

            }
        }catch(Exception e){

            String msg = "Error occurred while adding role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private int[] getUserIDS(DB dbConnection,String[] userList) throws MongoQueryException {

        String query = MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY;
        int userID[] = new int[userList.length];
        int index = 0;
        for(String user: userList) {

            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, query);
            if (query.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            prepStmt.setString("UM_USER_NAME",user);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()) {

                int id = (int) Double.parseDouble(cursor.next().get("UM_ID").toString());
                if(id > 0) {
                    userID[index] = (int) Double.parseDouble(cursor.next().get("UM_ID").toString());
                }
            }
            index++;
            prepStmt.close();
        }
        return userID;
    }

    protected void doDeleteRole(String roleName) throws UserStoreException {

        Map<String,Object> map = new HashMap<String, Object>();
        String mongoQuery1 = realmConfig
                .getUserStoreProperty(MongoDBRealmConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE);
        if (mongoQuery1 == null) {
            throw new UserStoreException("The mongo statement for delete user-role mapping is null");
        }
        String mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_ROLE);
        if (mongoQuery2 == null) {
            throw new UserStoreException("The mongo statement for delete role is null");
        }
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            map.put("UM_ROLE_NAME",roleName);
            if(mongoQuery1.contains(UserCoreConstants.UM_TENANT_COLUMN)){

                map.put("UM_TENANT_ID",tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery1, map);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery2, map);
            }else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery1, map);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery2, map);
            }
        }catch(Exception e){

            String msg = "Error occurred while deleting role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

	protected void doUpdateRoleName(String roleName, String newRoleName) throws UserStoreException {

        JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(roleName);
        Map<String,Object> map = new HashMap<String, Object>();
        if (isExistingRole(newRoleName)) {
            throw new UserStoreException("Role name: " + newRoleName
                    + " in the system. Please pick another role name.");
        }
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_ROLE_NAME);
        map.put("UM_ROLE_NAME",roleName);
        map.put("UM_NEW_ROLE_NAME",newRoleName);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for update role name is null");
        }
        DB dbConnection = null;
        try{

            roleName = ctx.getRoleName();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID",tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery,map);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery,map);
            }
        }catch(Exception e){
            String msg = "Error occurred while updating role name : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

	protected String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        String[] roles = new String[0];
        DB dbConnection = null;
        String mongoQuery = null;
        MongoPreparedStatement prepStmt = null;
        if (maxItemLimit == 0) {
            return roles;
        }
        try{

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if(dbConnection == null){

                throw new UserStoreException("null connection");
            }
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_ROLE_LIST);
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoQuery);
            prepStmt.setString("UM_ROLE_NAME",filter);
            if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){

                prepStmt.setInt("UM_TENANT_ID",tenantId);
            }
            byte count = 0;
            DBCursor cursor;
            try{

                cursor = prepStmt.find();
                if (cursor!= null) {
                    while (cursor.hasNext()) {
                        String name = cursor.next().get("UM_ROLE_NAME").toString();
                        // append the domain if exist
                        String domain =
                                realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                        name = UserCoreUtil.addDomainToName(name, domain);
                        lst.add(name);
                    }
                }
//
//			if (isSharedGroupEnabled()) {
//				lst.addAll(Arrays.asList(doGetSharedRoleNames(null, filter, maxItemLimit)));
//			}
//
                if (lst.size() > 0) {
                    roles = lst.toArray(new String[lst.size()]);
                }

            }catch(MongoQueryException e){

                String errorMessage =
                        "Error while fetching roles from JDBC user store according to filter : " + filter +
                                " & max item limit : " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);

            }
        }catch(Exception e){

            String msg = "Error occurred while retrieving role names for filter : " + filter + " & max item limit : " +
                    maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return roles;
	}

	protected String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        String[] users = new String[0];
        DB dbConnection = null;
        String mongoQuery = null;
        MongoPreparedStatement prepStmt = null;
        AggregationOutput cursor = null;
        if (maxItemLimit == 0) {
            return new String[0];
        }

        int givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;

        int searchTime = UserCoreConstants.MAX_SEARCH_TIME;

        try {
            givenMax = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        }
        try {
            searchTime = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = UserCoreConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }
        try {

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();

            dbConnection = loadUserStoreSpacificDataSoruce();

            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USER_FILTER);
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoQuery);
            prepStmt.setString("UM_USER_NAME",filter);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            try {
                cursor = prepStmt.aggregate();
            }catch (MongoException e) {
                String errorMessage =
                        "Error while fetching users according to filter : " + filter + " & max Item limit " +
                                ": " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
            if(cursor != null) {
                Iterator<DBObject> results = cursor.results().iterator();
                while (results.hasNext()) {

                    String name = results.next().get("UM_USER_NAME").toString();
                    if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(name)) {
                        continue;
                    }
                    // append the domain if exist
                    String domain = realmConfig
                            .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                    name = UserCoreUtil.addDomainToName(name, domain);
                    lst.add(name);
                }
            }
            if (lst.size() > 0) {
                users = lst.toArray(new String[lst.size()]);
            }
            Arrays.sort(users);
        }catch(Exception e){
            String msg = "Error occurred while retrieving users for filter : " + filter + " & max Item limit : " +
                    maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return users;
	}

	protected String[] doGetDisplayNamesForInternalRole(String[] userNames) throws UserStoreException {
		return userNames;
	}

	public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {

        String[] roles = doGetExternalRoleListOfUser(userName, "*");
        if (roles != null) {
            for (String role : roles) {
                if (role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
	}

	protected String[] doGetSharedRoleNames(String tenantDomain, String filter, int maxItemLimit) throws UserStoreException {

        String[] roles = new String[0];
        DB dbConnection = null;
        String mongoQuery = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;

        if (maxItemLimit == 0) {
            return roles;
        }
        try {

            if (!isSharedGroupEnabled()) {
                return roles;
            }

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_SHARED_ROLE_LIST);
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoQuery);
            byte count=0;
            prepStmt.setString("UM_ROLE_NAME",filter);
            try{
                cursor = prepStmt.find();
            }catch(MongoQueryException e){


                String errorMessage =
                        "Error while fetching roles from JDBC user store for tenant domain : " + tenantDomain +
                                " & filter : " + filter + "& max item limit : " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
            // Expected columns UM_ROLE_NAME, UM_TENANT_ID, UM_SHARED_ROLE
            if (cursor != null) {
                while (cursor.hasNext()) {
                    String name = cursor.next().get("UM_SHARED_ROLE").toString();
                    int roleTenantId = Integer.parseInt(cursor.next().get("UM_TENANT_ID").toString());
                    // append the domain if exist
                    String domain =
                            realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                    name = UserCoreUtil.addDomainToName(name, domain);
                    name = UserCoreUtil.addTenantDomainToEntry(name, String.valueOf(roleTenantId));
                    lst.add(name);
                }
            }

            if (lst.size() > 0) {
                roles = lst.toArray(new String[lst.size()]);
            }
        }catch(Exception e){
            String errorMessage =
                    "Error while retrieving roles from JDBC user store for tenant domain : " + tenantDomain +
                            " & filter : " + filter + "& max item limit : " + maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return roles;
	}

	protected String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException {
        RoleContext roleContext = createRoleContext(roleName);
        return getUserListOfMongoDBRole(roleContext, filter);
	}

    private String[] getUserListOfMongoDBRole(RoleContext ctx, String filter)throws UserStoreException {

        String roleName = ctx.getRoleName();
        String[] names = null;
        String mongoQuery = null;
        Map<String,Object> map = new HashMap<String, Object>();
        if (!ctx.isShared()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_IN_ROLE);
            if (mongoQuery == null) {
                throw new UserStoreException("The mongo statement for retrieving user roles is null");
            }
            map.put("role.UM_ROLE_NAME",roleName);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID",tenantId);
                map.put("role.UM_TENANT_ID",tenantId);
                map.put("userRole.UM_TENANT_ID",tenantId);
                names = getStringValuesFromDatabase(mongoQuery, map,true,true);
            } else {
                names = getStringValuesFromDatabase(mongoQuery, map,true,true);
            }
        }else if (ctx.isShared()) {
            map.put("UM_ROLE_NAME",roleName);
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_IN_SHARED_ROLE);
            names = getStringValuesFromDatabase(mongoQuery, map,true,true);
        }

        List<String> userList = new ArrayList<String>();

        String domainName =
                realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        if (names != null) {
            for (String user : names) {
                user = UserCoreUtil.addDomainToName(user, domainName);
                userList.add(user);
            }

            names = userList.toArray(new String[userList.size()]);
        }
        log.debug("Roles are not defined for the role name " + roleName);

        return names;
    }

    private DB loadUserStoreSpacificDataSoruce() throws UserStoreException{

        if(db == null) {
            return MongoDatabaseUtil.createRealmDataSource(realmConfig);
        }else{
            return db;
        }
    }


	public String[] getProfileNames(String userName) throws UserStoreException {

        userName = UserCoreUtil.removeDomainFromName(userName);
        String mongoQuery;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving  is null");
        }
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(this.db,MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER_MONGO_QUERY_CONDITION);
        prepStmt.setInt("UM_TENANT_ID",tenantId);
        prepStmt.setString("UM_USER_NAME",userName);
        String[] names = null;
        try {
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()){

                int userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
                Map<String,Object> map = new HashMap<String, Object>();
                map.put("UM_USER_ID",userId);
                if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    map.put("UM_TENANT_ID",tenantId);
                    names = getDistinctStringValues(mongoQuery, map);
                } else {
                    names = getDistinctStringValues(mongoQuery, map);
                }
                if (names.length == 0) {
                    names = new String[]{UserCoreConstants.DEFAULT_PROFILE};
                } else {
                    Arrays.sort(names);
                    if (Arrays.binarySearch(names, UserCoreConstants.DEFAULT_PROFILE) < 0) {
                        // we have to add the default profile
                        String[] newNames = new String[names.length + 1];
                        int i = 0;
                        for (i = 0; i < names.length; i++) {
                            newNames[i] = names[i];
                        }
                        newNames[i] = UserCoreConstants.DEFAULT_PROFILE;
                        names = newNames;
                    }
                }
            }
            return names;
        } catch (MongoQueryException e) {

            String errorMessage = "Error occurred while getting profile names from username : ";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
	}

	public String[] getAllProfileNames() throws UserStoreException {
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROFILE_NAMES);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving profile names is null");
        }
        String[] names;
        Map<String,Object> map = new HashMap<String, Object>();
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            map.put("UM_TENANT_ID",tenantId);
            names = getDistinctStringValues(mongoQuery,map);
        } else {
            names = getDistinctStringValues(mongoQuery,map);
        }

        return names;
	}

	public boolean isReadOnly() throws UserStoreException {
        if ("true".equalsIgnoreCase(realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY))) {
            return true;
        }
        return false;
	}

	public int getUserId(String username) throws UserStoreException {
        String mongoQuery;
        Map<String,Object> map = new HashMap<String, Object>();
        map.put("UM_USER_NAME",username);
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERID_FROM_USERNAME);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving ID is null");
        }
        int id = -1;
        DB dbConnection = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID",tenantId);
                id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery,map);
            } else {
                id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, map);
            }
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting user id from username : " + username;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return id;
	}

	public int getTenantId(String username) throws UserStoreException {
        if (this.tenantId != MultitenantConstants.SUPER_TENANT_ID) {
            throw new UserStoreException("Not allowed to perform this operation");
        }
        Map<String,Object> map = new HashMap<String, Object>();
        map.put("UM_USER_NAME",username);
        String mongoQuery;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_TENANT_ID_FROM_USERNAME);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving ID is null");
        }
        int id = -1;
        DB dbConnection = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, map);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting tenant ID from username : " + username;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return id;
	}

	public int getTenantId() throws UserStoreException {
        return this.tenantId;
	}

	public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant) throws org.wso2.carbon.user.api.UserStoreException {
        return getProperties((Tenant) tenant);
	}

	public boolean isMultipleProfilesAllowed() {
		return false;
	}

	public void addRememberMe(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {

	}

	public boolean isValidRememberMeToken(String userName, String token) throws org.wso2.carbon.user.api.UserStoreException {
        try {
            if (isExistingUser(userName)) {
                return isExistingRememberMeToken(userName, token);
            }
        } catch (Exception e) {
            log.error("Validating remember me token failed for" + userName);
            // not throwing exception.
            // because we need to seamlessly direct them to login uis
        }

        return false;
	}

	public Properties getDefaultUserStoreProperties() {

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

	public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        return this.realmConfig.getUserStoreProperties();
	}

	public boolean isBulkImportSupported() throws UserStoreException {
        return true;
	}

	public RealmConfiguration getRealmConfiguration() {
        return this.realmConfig;
	}

    protected void persistUser(String userName, Object credential, String[] roleList,
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
            dbConnection = loadUserStoreSpacificDataSoruce();
            String sqlStmt1 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER);

            String saltValue = null;

            if ("true".equals(realmConfig.getUserStoreProperties().get(
                    MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
                byte[] bytes = new byte[16];
                random.nextBytes(bytes);
                saltValue = Base64.encode(bytes);
            }

            password = this.preparePassword(password, saltValue);
            Map<String,Object> map = new HashMap<String, Object>();
            map.put("UM_USER_PASSWORD",password);
            map.put("UM_USER_NAME",userName);
            map.put("UM_REQUIRE_CHANGE",requirePasswordChange);
            map.put("UM_CHANGED_TIME",new Date());
            // do all 4 possibilities
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue == null)) {
                map.put("UM_SALT_VALUE","");
                map.put("UM_TENANT_ID",tenantId);
                this.updateUserValue(dbConnection,sqlStmt1,map);
            } else if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue != null)) {
                map.put("UM_SALT_VALUE",saltValue);
                map.put("UM_TENANT_ID",tenantId);
                this.updateUserValue(dbConnection,sqlStmt1,map);
            } else if (!sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)
                    && (saltValue == null)) {
                map.put("UM_SALT_VALUE",null);
                map.put("UM_TENANT_ID",0);
                this.updateUserValue(dbConnection,sqlStmt1,map);
            } else {
                map.put("UM_SALT_VALUE",null);
                map.put("UM_TENANT_ID",0);
                this.updateUserValue(dbConnection,sqlStmt1,map);
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
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY);
            prepStmt.setString("UM_USER_NAME",userName);
            int rolesID[] = getRolesIDS(dbConnection,roles);
            int userID = 0;
            if (sqlStmt2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID",tenantId);
                DBCursor cursor = prepStmt.find();
                userID = Integer.parseInt(cursor.next().get("UM_ID").toString());
            } else {
                DBCursor cursor = prepStmt.find();
                userID = Integer.parseInt(cursor.next().get("UM_ID").toString());
            }
            Map<String,Object> mapRole = new HashMap<String, Object>();
            mapRole.put("UM_TENANT_ID",tenantId);
            mapRole.put("UM_USER_ID",userID);
            mapRole.put("UM_ROLE_ID",rolesID);
            MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, sqlStmt2,
                    mapRole);

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

    private int[] getRolesIDS(DB dbConnection, String[] roles) throws MongoQueryException {

        String query = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
        int rolesID[] = new int[roles.length];
        int index = 0;
        for(String role: roles) {

            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, query);
            if (query.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            prepStmt.setString("UM_ROLE_NAME",role);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()) {

                int id = (int) Double.parseDouble(cursor.next().get("UM_ID").toString());
                if(id > 0) {
                    rolesID[index] = id;
                }
            }
            index++;
            prepStmt.close();
        }
        return rolesID;
    }

    protected void updateUserValue(DB connection,String query,Map<String,Object> map) throws UserStoreException {

        JSONObject jsonKeys = new JSONObject(query);
        List<String> keys = MongoDatabaseUtil.getKeys(jsonKeys);
        try{
            int id = MongoDatabaseUtil.getIncrementedSequence(connection,"UM_USER");
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(connection,query);
            Iterator<String> searchKeys = keys.iterator();
            while(searchKeys.hasNext()) {
                String key = searchKeys.next();
                if (!key.equals("collection") || !key.equals("projection") || !key.equals("$set")) {
                    for (Map.Entry<String, Object> entry : map.entrySet()) {
                        if(entry.getKey().equals(key)) {
                            if(entry.getValue() == null){
                                prepStmt.setString(key,null);
                            }else if(entry.getValue() instanceof String){
                                prepStmt.setString(key,(String)entry.getValue());
                            }else if(entry.getValue() instanceof Date){
                                prepStmt.setDate(key,(Date)entry.getValue());
                            }else if(entry.getValue() instanceof Integer){
                                prepStmt.setInt(key,(Integer)entry.getValue());
                            }else if(entry.getValue() instanceof Boolean){
                                prepStmt.setBoolean(key,(Boolean) entry.getValue());
                            }
                        }
                    }
                }
            }
            if(MongoDatabaseUtil.updateTrue(keys)){

                prepStmt.update();
            }
            else{
                prepStmt.setInt("UM_ID",id);
                prepStmt.insert();
            }

        }catch(MongoQueryException e){

            log.error("Error! "+e.getMessage(),e);
            log.error("Using json "+query);
            throw new UserStoreException("Error! "+e.getMessage(),e);
        }catch(Exception ex){

            log.error("Error! "+ex.getMessage(),ex);
            log.error("Using json "+query);
            throw new UserStoreException("Error! "+ex.getMessage(),ex);
        }finally {
            MongoDatabaseUtil.closeConnection(connection);
        }

    }

    public void addProperty(DB dbConnection, String userName, String propertyName,
                            String value, String profileName) throws UserStoreException {

        try {

            String mongoStmt = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_PROPERTY);
            String query = MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1;
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,query);
            prepStmt.setString("UM_USER_NAME",userName);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()) {

                int userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
                Map<String, Object> map = new HashMap<String, Object>();
                map.put("UM_USER_ID",userId);
                map.put("UM_ATTR_NAME",propertyName);
                map.put("UM_ATTR_VALUE",value);
                map.put("UM_PROFILE_ID",profileName);
                if (mongoStmt == null) {
                    throw new UserStoreException("The mongo query statement for add user property sql is null");
                }

                if(mongoStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    map.put("UM_TENANT_ID",tenantId);
                        updateStringValuesToDatabase(dbConnection, mongoStmt,map);
                }else{
                        updateStringValuesToDatabase(dbConnection, mongoStmt, map);
                }
            }
        } catch (Exception e) {
            String msg = "Error occurred while adding user property for user : " + userName + " & property name : " +
                    propertyName + " & value : " + value;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }
    }

    protected boolean checkExistingUserName(String userName) throws UserStoreException {

        boolean isExisting = false;
        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if(this.db==null){

            this.db = loadUserStoreSpacificDataSoruce();
        }
        this.collection = this.db.getCollection("UM_USER");
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
            if(cursor != null) {
                isExisting = cursor.hasNext();
            }
        }
        return isExisting;
    }

    public boolean isExistingRememberMeToken(String userName, String token)
            throws org.wso2.carbon.user.api.UserStoreException {
        boolean isValid = false;
        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        String value = null;
        Date createdTime = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            prepStmt = new MongoPreparedStatementImpl(dbConnection,HybridMongoDBConstants.GET_REMEMBERME_VALUE_MONGO_QUERY);
            prepStmt.setString("UM_USER_NAME", userName);
            prepStmt.setInt("UM_TENANT_ID", tenantId);
            cursor = prepStmt.find();
            while (cursor.hasNext()) {
                value = cursor.next().get("UM_COOKIE_VALUE").toString();
                createdTime = (Date) cursor.next().get("UM_CREATED_TIME");
                createdTime = new Date(new BSONTimestamp((int)createdTime.getTime(),1).getTime());
            }
        } catch (MongoQueryException e) {
            log.error("Using sql : " + HybridMongoDBConstants.GET_REMEMBERME_VALUE_MONGO_QUERY);
            throw new UserStoreException(e.getMessage(), e);
        } finally {

            MongoDatabaseUtil.closeAllConnections(dbConnection,prepStmt);
        }

        if (value != null && createdTime != null) {
            Calendar calendar = Calendar.getInstance();
            Date nowDate = calendar.getTime();
            calendar.setTime(createdTime);
            calendar.add(Calendar.SECOND, CarbonConstants.REMEMBER_ME_COOKIE_TTL);
            Date expDate = calendar.getTime();
            if (expDate.before(nowDate)) {
                // Do nothing remember me expired.
                // Return the user gracefully
                log.debug("Remember me token has expired !!");
            } else {

                // We also need to compare the token
                if (value.equals(token)) {
                    isValid = true;
                } else {
                    log.debug("Remember me token in DB and token in request are different !!");
                    isValid = false;
                }
            }
        }

        return isValid;
    }

    public class RoleBreakdown {
        private String[] roles;
        private Integer[] tenantIds;

        private String[] sharedRoles;
        private Integer[] sharedTenantids;

        public String[] getRoles() {
            return roles;
        }

        public void setRoles(String[] roles) {
            this.roles = roles;
        }

        public Integer[] getTenantIds() {
            return tenantIds;
        }

        public void setTenantIds(Integer[] tenantIds) {
            this.tenantIds = tenantIds;
        }

        public String[] getSharedRoles() {
            return sharedRoles;
        }

        public void setSharedRoles(String[] sharedRoles) {
            this.sharedRoles = sharedRoles;
        }

        public Integer[] getSharedTenantids() {
            return sharedTenantids;
        }

        public void setSharedTenantids(Integer[] sharedTenantids) {
            this.sharedTenantids = sharedTenantids;
        }

    }
    private boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

    protected void persistDomain() throws UserStoreException{

        String domain = UserCoreUtil.getDomainName(this.realmConfig);
        if (domain != null) {
          //  MongoUserCoreUtil.persistDomain(domain, this.tenantId, this.db);
            UserCoreUtil.persistDomain(domain,this.tenantId,dataSource);
        }
    }

    protected void addInitialAdminData(boolean addAdmin, boolean initialSetup) throws UserStoreException {

        if (realmConfig.getAdminRoleName() == null || realmConfig.getAdminUserName() == null) {
            log.error("Admin user name or role name is not valid. Please provide valid values.");
            throw new UserStoreException(
                    "Admin user name or role name is not valid. Please provide valid values.");
        }
        String adminUserName = UserCoreUtil.removeDomainFromName(realmConfig.getAdminUserName());
        String adminRoleName = UserCoreUtil.removeDomainFromName(realmConfig.getAdminRoleName());
        boolean userExist = false;
        boolean roleExist = false;
        boolean isInternalRole = false;
        try {
            if (Boolean.parseBoolean(this.getRealmConfiguration().getUserStoreProperty(
                    UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED))) {
                roleExist = doCheckExistingRole(adminRoleName);
            }
        } catch (Exception e) {
            //ignore
        }

        if (!roleExist) {
            try {
                roleExist = hybridRoleManager.isExistingRole(adminRoleName);
            } catch (Exception e) {
                //ignore
            }
            if (roleExist) {
                isInternalRole = true;
            }
        }

        try {
            userExist = doCheckExistingUser(adminUserName);
        } catch (Exception e) {
            //ignore
        }

        if (!userExist) {
            if (isReadOnly()) {
                String message = "Admin user can not be created in primary user store. " +
                        "User store is read only. " +
                        "Please pick a user name which is exist in the primary user store as Admin user";
                if (initialSetup) {
                    throw new UserStoreException(message);
                } else if (log.isDebugEnabled()) {
                    log.error(message);
                }
            } else if (addAdmin) {
                try {
                    this.doAddUser(adminUserName, realmConfig.getAdminPassword(),
                            null, null, null, false);
                } catch (Exception e) {
                    String message = "Admin user has not been created. " +
                            "Error occurs while creating Admin user in primary user store.";
                    if (initialSetup) {
                        throw new UserStoreException(message, e);
                    } else if (log.isDebugEnabled()) {
                        log.error(message, e);
                    }
                }
            } else {
                if (initialSetup) {
                    String message = "Admin user can not be created in primary user store. " +
                            "Add-Admin has been set to false. " +
                            "Please pick a User name which is exist in the primary user store as Admin user";
                    if (initialSetup) {
                        throw new UserStoreException(message);
                    } else if (log.isDebugEnabled()) {
                        log.error(message);
                    }
                }
            }
        }

        if (!roleExist) {
            if (addAdmin) {
                if (!isReadOnly() && writeGroupsEnabled) {
                    try {
                        this.doAddRole(adminRoleName, new String[]{adminUserName}, false);
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        String message = "Admin role has not been created. " +
                                "Error occurs while creating Admin role in primary user store.";
                        if (initialSetup) {
                            throw new UserStoreException(message, e);
                        } else if (log.isDebugEnabled()) {
                            log.error(message, e);
                        }
                    }
                } else {
                    // creates internal role
                    try {
                        hybridRoleManager.addHybridRole(adminRoleName, new String[]{adminUserName});
                        isInternalRole = true;
                    } catch (Exception e) {
                        String message = "Admin role has not been created. " +
                                "Error occurs while creating Admin role in primary user store.";
                        if (initialSetup) {
                            throw new UserStoreException(message, e);
                        } else if (log.isDebugEnabled()) {
                            log.error(message, e);
                        }
                    }
                }
            } else {
                String message = "Admin role can not be created in primary user store. " +
                        "Add-Admin has been set to false. " +
                        "Please pick a Role name which is exist in the primary user store as Admin Role";
                if (initialSetup) {
                    throw new UserStoreException(message);
                } else if (log.isDebugEnabled()) {
                    log.error(message);
                }
            }
        }

        if (isInternalRole) {
            if (!hybridRoleManager.isUserInRole(adminUserName, adminRoleName)) {
                try {
                    hybridRoleManager.updateHybridRoleListOfUser(adminUserName, null,
                            new String[]{adminRoleName});
                } catch (Exception e) {
                    String message = "Admin user has not been assigned to Admin role. " +
                            "Error while assignment is done";
                    if (initialSetup) {
                        throw new UserStoreException(message, e);
                    } else if (log.isDebugEnabled()) {
                        log.error(message, e);
                    }
                }
            }
            realmConfig.setAdminRoleName(UserCoreUtil.addInternalDomainName(adminRoleName));
        } else if (!isReadOnly() && writeGroupsEnabled) {
            if (!this.doCheckIsUserInRole(adminUserName, adminRoleName)) {
                if (addAdmin) {
                    try {
                        this.doUpdateRoleListOfUser(adminUserName, null,
                                new String[]{adminRoleName});
                    } catch (Exception e) {
                        String message = "Admin user has not been assigned to Admin role. " +
                                "Error while assignment is done";
                        if (initialSetup) {
                            throw new UserStoreException(message, e);
                        } else if (log.isDebugEnabled()) {
                            log.error(message, e);
                        }
                    }
                } else {
                    String message = "Admin user can not be assigned to Admin role " +
                            "Add-Admin has been set to false. Please do the assign it in user store level";
                    if (initialSetup) {
                        throw new UserStoreException(message);
                    } else if (log.isDebugEnabled()) {
                        log.error(message);
                    }
                }
            }
        }

        doInitialUserAdding();
    }

    protected void doInitialSetup() throws UserStoreException {
       // systemMongoUserRoleManager = new SystemMongoUserRoleManager(this.db, tenantId);
        //mongoDBRoleManager = new HybridMongoDBRoleManager(this.db, tenantId, realmConfig, userRealm);
        systemUserRoleManager = new SystemUserRoleManager(dataSource,tenantId);
        hybridRoleManager = new HybridRoleManager(dataSource,tenantId,realmConfig,userRealm);
    }

    protected String[] doGetInternalRoleListOfUser(String userName, String filter) throws UserStoreException {
        if (Boolean.parseBoolean(realmConfig.getUserStoreProperty(MULIPLE_ATTRIBUTE_ENABLE))) {
            String userNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
            if (userNameAttribute != null && userNameAttribute.trim().length() > 0) {
                Map<String, String> map = getUserPropertyValues(userName, new String[]{userNameAttribute}, null);
                userName = map.get(userNameAttribute);
            }
        }
        log.debug("Retrieving internal roles for user name :  " + userName + " and search filter " + filter);
        return hybridRoleManager.getHybridRoleListOfUser(userName, filter);
    }


    /**
     * This method is used by the APIs' in the AbstractUserStoreManager
     * to make compatible with Java Security Manager.
     */
    private Object callSecure(final String methodName, final Object[] objects, final Class[] argTypes)
            throws UserStoreException {

        final MongoDBUserStoreManager instance = this;

        isSecureCall.set(Boolean.TRUE);
        final Method method;
        try {
            Class clazz = Class.forName("org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager");
            method = clazz.getDeclaredMethod(methodName, argTypes);

        } catch (NoSuchMethodException e) {
            log.error("Error occurred when calling method " + methodName, e);
            throw new UserStoreException(e);
        } catch (ClassNotFoundException e) {
            log.error("Error occurred when calling class " + methodName, e);
            throw new UserStoreException(e);
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
                public Object run() throws Exception {
                    return method.invoke(instance, objects);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() != null && e.getCause().getCause() != null && e.getCause().getCause() instanceof
                    UserStoreException) {
                // Actual UserStoreException get wrapped with two exceptions
                throw new UserStoreException(e.getCause().getCause().getMessage(), e);

            } else {
                String msg = "Error occurred while accessing Java Security Manager Privilege Block";
                log.error(msg);
                throw new UserStoreException(msg, e);
            }
        } finally {
            isSecureCall.set(Boolean.FALSE);
        }
    }




    public boolean isExistingRole(String roleName, boolean shared) throws org.wso2.carbon.user.api.UserStoreException {
        if (shared) {
            return isExistingShareRole(roleName);
        } else {
            return isExistingRole(roleName);
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isExistingRole(String roleName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            Object object = callSecure("isExistingRole", new Object[]{roleName}, argTypes);
            return (Boolean) object;
        }

        UserStore userStore = getUserStore(roleName);

        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().isExistingRole(userStore.getDomainFreeName());
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (userStore.isSystemStore()) {
            return systemUserRoleManager.isExistingRole(userStore.getDomainFreeName());
        }

        if (userStore.isHybridRole()) {
            boolean exist;

            if (!UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStore.getDomainName())) {
                exist = hybridRoleManager.isExistingRole(userStore.getDomainAwareName());
            } else {
                exist = hybridRoleManager.isExistingRole(userStore.getDomainFreeName());
            }

            return exist;
        }

        // This happens only once during first startup - adding administrator user/role.
        roleName = userStore.getDomainFreeName();

        // you can not check existence of shared role using this method.
        if (isSharedGroupEnabled() && roleName.contains(UserCoreConstants.TENANT_DOMAIN_COMBINER)) {
            return false;
        }

        boolean isExisting = doCheckExistingRole(roleName);

        if (!isExisting && (isReadOnly() || !readGroupsEnabled)) {
            isExisting = hybridRoleManager.isExistingRole(roleName);
        }

        if (!isExisting) {
            if (systemUserRoleManager.isExistingRole(roleName)) {
                isExisting = true;
            }
        }

        return isExisting;
    }

//////////////////////////////////// Shared role APIs start //////////////////////////////////////////

    /**
     * TODO move to API
     *
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public boolean isExistingShareRole(String roleName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            Object object = callSecure("isExistingShareRole", new Object[]{roleName}, argTypes);
            return (Boolean) object;
        }

        UserStoreManager manager = getUserStoreWithSharedRoles();

        if (manager == null) {
            throw new UserStoreException("Share Groups are not supported by this realm");
        }

        return ((MongoDBUserStoreManager) manager).doCheckExistingRole(roleName);
    }

    /**
     * {@inheritDoc}
     */
    public final boolean authenticate(final String userName, final Object credential) throws UserStoreException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                public Boolean run() throws Exception {
                    if (userName == null || credential == null) {
                        log.error("Authentication failure. Either Username or Password is null");
                        return false;
                    }
                    int index = userName != null ? userName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) : -1;
                    boolean domainProvided = index > 0;
                    return authenticate(userName, credential, domainProvided);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }
    }

    protected boolean authenticate(final String userName, final Object credential, final boolean domainProvided)
            throws UserStoreException {

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                public Boolean run() throws Exception {
                    return authenticateInternal(userName, credential, domainProvided);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }

    }

    /**
     * @param userName
     * @param credential
     * @param domainProvided
     * @return
     * @throws UserStoreException
     */
    private boolean authenticateInternal(String userName, Object credential, boolean domainProvided)
            throws UserStoreException {

        boolean authenticated = false;

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive() && userStore.getUserStoreManager() instanceof MongoDBUserStoreManager) {
            return ((MongoDBUserStoreManager) userStore.getUserStoreManager()).authenticate(userStore.getDomainFreeName(),
                    credential, domainProvided);
        }

        // #################### Domain Name Free Zone Starts Here ################################

        // #################### <Listeners> #####################################################
        for (UserStoreManagerListener listener : UMListenerServiceComponent
                .getUserStoreManagerListeners()) {
            if (!listener.authenticate(userName, credential, this)) {
                return true;
            }
        }

        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreAuthenticate(userName, credential, this)) {
                return false;
            }
        }
        // #################### </Listeners> #####################################################

        int tenantId = getTenantId();

        try {
            RealmService realmService = UserCoreUtil.getRealmService();
            if (realmService != null) {
                boolean tenantActive = realmService.getTenantManager().isTenantActive(tenantId);

                if (!tenantActive) {
                    log.warn("Tenant has been deactivated. TenantID : " + tenantId);
                    return false;
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while trying to check Tenant status for Tenant : "
                    + tenantId, e);
        }

        // We are here due to two reason. Either there is no secondary UserStoreManager or no
        // domain name provided with user name.

        try {
            // Let's authenticate with the primary UserStoreManager.
            authenticated = doAuthenticate(userName, credential);
        } catch (Exception e) {
            // We can ignore and proceed. Ignore the results from this user store.
            log.error(e);
            authenticated = false;
        }

        if (authenticated) {
            // Set domain in thread local variable for subsequent operations
            String domain = UserCoreUtil.getDomainName(this.realmConfig);
            if (domain != null) {
                UserCoreUtil.setDomainInThreadLocal(domain.toUpperCase());
            }
        }

        // If authentication fails in the previous step and if the user has not specified a
        // domain- then we need to execute chained UserStoreManagers recursively.
        if (!authenticated && !domainProvided && this.getSecondaryUserStoreManager() != null) {
            authenticated = ((MongoDBUserStoreManager) this.getSecondaryUserStoreManager())
                    .authenticate(userName, credential, domainProvided);
        }

        // You cannot change authentication decision in post handler to TRUE
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostAuthenticate(userName, authenticated, this)) {
                return false;
            }
        }

        if (log.isDebugEnabled()) {
            if (!authenticated) {
                log.debug("Authentication failure. Wrong username or password is provided.");
            }
        }

        return authenticated;
    }

    /**
     * {@inheritDoc}
     */
    public final String getUserClaimValue(String userName, String claim, String profileName)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class, String.class};
            Object object = callSecure("getUserClaimValue", new Object[]{userName, claim, profileName}, argTypes);
            return (String) object;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().getUserClaimValue(userStore.getDomainFreeName(),
                    claim, profileName);
        }

        // #################### Domain Name Free Zone Starts Here ################################
        // If user does not exist, throw an exception

        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }

        Map<String, String> finalValues = doGetUserClaimValues(userName, new String[]{claim},
                userStore.getDomainName(), profileName);

        String value = null;

        if (finalValues != null) {
            value = finalValues.get(claim);
        }

        // #################### <Listeners> #####################################################

        List<String> list = new ArrayList<String>();
        if (value != null) {
            list.add(value);
        }

        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (listener instanceof AbstractUserOperationEventListener) {
                AbstractUserOperationEventListener newListener = (AbstractUserOperationEventListener) listener;
                if (!newListener.doPostGetUserClaimValue(userName, claim, list, profileName, this)) {
                    break;
                }
            }
        }
        // #################### </Listeners> #####################################################

        return value;
    }

    /**
     * {@inheritDoc}
     */
    public final Map<String, String> getUserClaimValues(String userName, String[] claims,
                                                        String profileName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String[].class, String.class};
            Object object = callSecure("getUserClaimValues", new Object[]{userName, claims, profileName}, argTypes);
            return (Map<String, String>) object;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().getUserClaimValues(
                    userStore.getDomainFreeName(), claims, profileName);
        }

        // #################### Domain Name Free Zone Starts Here ################################
        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }
        // check for null claim list
        if (claims == null) {
            claims = new String[0];
        }
        Map<String, String> finalValues = doGetUserClaimValues(userName, claims,
                userStore.getDomainName(), profileName);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (listener instanceof AbstractUserOperationEventListener) {
                AbstractUserOperationEventListener newListener = (AbstractUserOperationEventListener) listener;
                if (!newListener.doPostGetUserClaimValues(userStore.getDomainFreeName(), claims, profileName,
                        finalValues, this)) {
                    break;
                }
            }
        }
        // #################### </Listeners> #####################################################

        return finalValues;
    }


    /**
     * If the claim is domain qualified, search the users respective user store. Else we
     * return the users in all the user-stores recursively
     * {@inheritDoc}
     */
    public final String[] getUserList(String claim, String claimValue, String profileName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class, String.class};
            Object object = callSecure("getUserList", new Object[]{claim, claimValue, profileName}, argTypes);
            return (String[]) object;
        }

        String property;
        //extracting the domain from claimValue. Not introducing a new method due to carbon patch process..
        String extractedDomain = null;
        int index;
        index = claimValue.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
        if (index > 0) {
            String names[] = claimValue.split(CarbonConstants.DOMAIN_SEPARATOR);
            extractedDomain = names[0].trim();
        } else {
            extractedDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }

        UserStoreManager userManager = getSecondaryUserStoreManager(extractedDomain);
        if (USERNAME_CLAIM_URI.equalsIgnoreCase(claim)) {
            if (userManager.isExistingUser(claimValue)) {
                return new String[]{claimValue};
            } else {
                return new String[]{};
            }
        }

        claimValue = UserCoreUtil.removeDomainFromName(claimValue);
        //if domain is present, then we search within that domain only
        if (!extractedDomain.equals(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME)) {
            try{
                property = claimManager.getAttributeName(extractedDomain, claim);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException("Error occurred while retrieving attribute name for domain : " +
                        extractedDomain + " and claim " + claim);
            }
            if (property == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not find matching property for\n" +
                            "claim :" + claim +
                            "domain :" + extractedDomain);
                }
                return new String[0];
            }
            if (getSecondaryUserStoreManager(extractedDomain) instanceof MongoDBUserStoreManager) {
                // get the user list and return with domain appended
                MongoDBUserStoreManager userStoreManager = (MongoDBUserStoreManager)
                        getSecondaryUserStoreManager(extractedDomain);
                String[] userArray = userStoreManager.getUserListFromProperties(property, claimValue, profileName);
                return UserCoreUtil.addDomainToNames(userArray, extractedDomain);
            }
        }
        //if no domain is given then search all the user stores
        List<String> usersFromAllStoresList = new LinkedList<String>();
        if (this instanceof MongoDBUserStoreManager) {
            MongoDBUserStoreManager currentUserStoreManager = this;
            if (log.isDebugEnabled()) {
                log.debug("No domain name found in claim value. Searching through all user stores for possible matches");
            }
            do {
                String currentDomain = currentUserStoreManager.getMyDomainName();
                try {
                    property = claimManager.getAttributeName(currentDomain, claim);
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    throw new UserStoreException("Error occurred while retrieving attribute name for domain : " +
                            currentDomain + " and claim " + claim);
                }
                if (property == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Could not find matching property for\n" +
                                "claim :" + claim +
                                "domain :" + currentDomain);
                    }
                    continue; // continue look in other stores
                }
                String[] userArray2 = currentUserStoreManager.getUserListFromProperties(property, claimValue, profileName);
                if (log.isDebugEnabled()) {
                    log.debug("searching the property :" + property + "in user store" + currentDomain +
                            "for given claim value : " + claimValue);
                }
                String[] userWithDomainArray = UserCoreUtil.addDomainToNames(userArray2, currentDomain);
                usersFromAllStoresList.addAll(Arrays.asList(userWithDomainArray));
            } while ((currentUserStoreManager.getSecondaryUserStoreManager() instanceof MongoDBUserStoreManager) &&
                    ((currentUserStoreManager = (MongoDBUserStoreManager)
                            currentUserStoreManager.getSecondaryUserStoreManager()) != null));
        }
        //done with all user store processing. Return the user array if not empty
        String[] fullUserList = usersFromAllStoresList.toArray(new String[0]);
        Arrays.sort(fullUserList);
        return fullUserList;
    }

    /**
     * {@inheritDoc}
     */
    public final void updateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, Object.class, Object.class};
            callSecure("updateCredential", new Object[]{userName, newCredential, oldCredential}, argTypes);
            return;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().updateCredential(userStore.getDomainFreeName(),
                    newCredential, oldCredential);
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + " Invalid operation. User store is read only");
        }

        // #################### <Listeners> #####################################################
        for (UserStoreManagerListener listener : UMListenerServiceComponent
                .getUserStoreManagerListeners()) {
            if (!listener.updateCredential(userName, newCredential, oldCredential, this)) {
                return;
            }
        }

        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreUpdateCredential(userName, newCredential, oldCredential, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        // This user name here is domain-less.
        // We directly authenticate user against the selected UserStoreManager.
        boolean isAuth = this.doAuthenticate(userName, oldCredential);

        if (isAuth) {

            if (!checkUserPasswordValid(newCredential)) {
                String errorMsg = realmConfig
                        .getUserStoreProperty(PROPERTY_PASSWORD_ERROR_MSG);

                if (errorMsg != null) {
                    throw new UserStoreException(errorMsg);
                }

                throw new UserStoreException(
                        "Credential not valid. Credential must be a non null string with following format, "
                                + realmConfig
                                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));

            }


            this.doUpdateCredential(userName, newCredential, oldCredential);

            // #################### <Listeners> ##################################################
            for (UserOperationEventListener listener : UMListenerServiceComponent
                    .getUserOperationEventListeners()) {
                if (!listener.doPostUpdateCredential(userName, newCredential, this)) {
                    return;
                }
            }
            // #################### </Listeners> ##################################################

            return;
        } else {
            throw new UserStoreException(
                    INVALID_PASSWORD + " Old credential does not match with the existing credentials.");
        }
    }

    /**
     * {@inheritDoc}
     */
    public final void updateCredentialByAdmin(String userName, Object newCredential)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, Object.class};
            callSecure("updateCredentialByAdmin", new Object[]{userName, newCredential}, argTypes);
            return;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().updateCredentialByAdmin(userStore.getDomainFreeName(),
                    newCredential);
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + "Invalid operation. User store is read only");
        }

        // #################### <Listeners> #####################################################
        for (UserStoreManagerListener listener : UMListenerServiceComponent
                .getUserStoreManagerListeners()) {
            if (!listener.updateCredentialByAdmin(userName, newCredential, this)) {
                return;
            }
        }
        // using string buffers to allow the password to be changed by listener
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (newCredential == null) { // a default password will be set
                StringBuffer credBuff = new StringBuffer();
                if (!listener.doPreUpdateCredentialByAdmin(userName, newCredential, this)) {
                    return;
                }
                newCredential = credBuff.toString(); // reading the modified value
            } else if (newCredential instanceof String) {
                StringBuffer credBuff = new StringBuffer((String) newCredential);
                if (!listener.doPreUpdateCredentialByAdmin(userName, credBuff, this)) {
                    return;
                }
                newCredential = credBuff.toString(); // reading the modified value
            }
        }
        // #################### </Listeners> #####################################################

        doUpdateCredentialByAdmin(userName, newCredential);

        if (!checkUserPasswordValid(newCredential)) {
            String errorMsg = realmConfig
                    .getUserStoreProperty(PROPERTY_PASSWORD_ERROR_MSG);

            if (errorMsg != null) {
                throw new UserStoreException(errorMsg);
            }

            throw new UserStoreException(
                    "Credential not valid. Credential must be a non null string with following format, "
                            + realmConfig
                            .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));

        }

        if (!doCheckExistingUser(userStore.getDomainFreeName())) {
            throw new UserStoreException("User " + userName + " does not exisit in the user store");
        }


        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostUpdateCredentialByAdmin(userName, newCredential, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * Get the attribute for the provided claim uri and identifier.
     *
     * @param claimURI
     * @param identifier user name or role.
     * @param domainName TODO
     * @return claim attribute value. NULL if attribute is not defined for the
     * claim uri
     * @throws org.wso2.carbon.user.api.UserStoreException
     */
    protected String getClaimAtrribute(String claimURI, String identifier, String domainName)
            throws org.wso2.carbon.user.api.UserStoreException {

        domainName =
                (domainName == null || domainName.length()==0)
                        ? (identifier.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > -1
                        ? identifier.split(UserCoreConstants.DOMAIN_SEPARATOR)[0]
                        : realmConfig.getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME))
                        : domainName;
        String attributeName = null;

        if (domainName != null && !domainName.equals(UserStoreConfigConstants.PRIMARY)) {
            attributeName = claimManager.getAttributeName(domainName, claimURI);
        }
        if (attributeName == null || attributeName.length()==0) {
            attributeName = claimManager.getAttributeName(claimURI);
        }

        if (attributeName == null) {
            if (UserCoreConstants.PROFILE_CONFIGURATION.equals(claimURI)) {
                attributeName = claimURI;
            } else if (DISAPLAY_NAME_CLAIM.equals(claimURI)) {
                attributeName = this.realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
            } else {
                throw new UserStoreException("Mapped attribute cannot be found for claim : " + claimURI + " in user " +
                        "store : " + getMyDomainName());
            }
        }

        return attributeName;
    }

    /**
     * {@inheritDoc}
     */
    public final void deleteUser(String userName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            callSecure("deleteUser", new Object[]{userName}, argTypes);
            return;
        }

        String loggedInUser = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (loggedInUser != null) {
            loggedInUser = UserCoreUtil.addDomainToName(loggedInUser, UserCoreUtil.getDomainFromThreadLocal());
            if ((loggedInUser.indexOf(UserCoreConstants.DOMAIN_SEPARATOR)) < 0) {
                loggedInUser = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME +
                        CarbonConstants.DOMAIN_SEPARATOR + loggedInUser;
            }
        }

        String deletingUser = UserCoreUtil.addDomainToName(userName, getMyDomainName());
        if ((deletingUser.indexOf(UserCoreConstants.DOMAIN_SEPARATOR)) < 0) {
            deletingUser = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME +
                    CarbonConstants.DOMAIN_SEPARATOR + deletingUser;
        }

        if (loggedInUser != null && loggedInUser.equals(deletingUser)) {
            log.debug("User " + loggedInUser + " tried to delete him/her self");
            throw new UserStoreException(LOGGED_IN_USER + " Cannot delete logged in user");
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().deleteUser(userStore.getDomainFreeName());
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (UserCoreUtil.isPrimaryAdminUser(userName, realmConfig)) {
            throw new UserStoreException(ADMIN_USER + "Cannot delete admin user");
        }

        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
            throw new UserStoreException(ANONYMOUS_USER + "Cannot delete anonymous user");
        }

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + " Invalid operation. User store is read only");
        }

        // #################### <Listeners> #####################################################
        for (UserStoreManagerListener listener : UMListenerServiceComponent
                .getUserStoreManagerListeners()) {
            if (!listener.deleteUser(userName, this)) {
                return;
            }
        }

        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreDeleteUser(userName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException("Cannot delete user who is not exist");
        }

        // Remove users from internal role mapping
        hybridRoleManager.deleteUser(UserCoreUtil.addDomainToName(userName, getMyDomainName()));

        doDeleteUser(userName);

        // Needs to clear roles cache upon deletion of a user
        clearUserRolesCache(UserCoreUtil.addDomainToName(userName, getMyDomainName()));

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostDeleteUser(userName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * {@inheritDoc}
     */
    public final void setUserClaimValue(String userName, String claimURI, String claimValue,
                                        String profileName) throws UserStoreException {

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().setUserClaimValue(userStore.getDomainFreeName(),
                    claimURI, claimValue, profileName);
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + " Invalid operation. User store is read only");
        }

        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreSetUserClaimValue(userName, claimURI, claimValue, profileName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################


        doSetUserClaimValue(userName, claimURI, claimValue, profileName);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostSetUserClaimValue(userName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * {@inheritDoc}
     */
    public final void setUserClaimValues(String userName, Map<String, String> claims,
                                         String profileName) throws UserStoreException {

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().setUserClaimValues(userStore.getDomainFreeName(),
                    claims, profileName);
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + "Invalid operation. User store is read only");
        }

        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }
        if (claims == null) {
            claims = new HashMap<String, String>();
        }
        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreSetUserClaimValues(userName, claims, profileName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        doSetUserClaimValues(userName, claims, profileName);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostSetUserClaimValues(userName, claims, profileName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * {@inheritDoc}
     */
    public final void deleteUserClaimValue(String userName, String claimURI, String profileName)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class, String.class};
            callSecure("deleteUserClaimValue", new Object[]{userName, claimURI, profileName}, argTypes);
            return;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().deleteUserClaimValue(userStore.getDomainFreeName(),
                    claimURI, profileName);
            return;
        }

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + " Invalid operation. User store is read only");
        }

        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreDeleteUserClaimValue(userName, claimURI, profileName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################



        doDeleteUserClaimValue(userName, claimURI, profileName);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostDeleteUserClaimValue(userName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################
    }

    /**
     * {@inheritDoc}
     */
    public final void deleteUserClaimValues(String userName, String[] claims, String profileName)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String[].class, String.class};
            callSecure("deleteUserClaimValues", new Object[]{userName, claims, profileName}, argTypes);
            return;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().deleteUserClaimValues(userStore.getDomainFreeName(),
                    claims, profileName);
            return;
        }

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + " Invalid operation. User store is read only");
        }

        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }

        if (claims == null) {
            claims = new String[0];
        }
        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreDeleteUserClaimValues(userName, claims, profileName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################


        doDeleteUserClaimValues(userName, claims, profileName);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostDeleteUserClaimValues(userName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * {@inheritDoc}
     */
    public final void addUser(String userName, Object credential, String[] roleList,
                              Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, Object.class, String[].class, Map.class, String.class,
                    boolean.class};
            callSecure("addUser", new Object[]{userName, credential, roleList, claims, profileName,
                    requirePasswordChange}, argTypes);
            return;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().addUser(userStore.getDomainFreeName(), credential,
                    roleList, claims, profileName, requirePasswordChange);
            return;
        }
        if (userStore.isSystemStore()) {
            systemUserRoleManager.addSystemUser(userName, credential, roleList);
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(INVALID_OPERATION + " Invalid operation. User store is read only");
        }

        // This happens only once during first startup - adding administrator user/role.
        if (userName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
            userName = userStore.getDomainFreeName();
            roleList = UserCoreUtil.removeDomainFromNames(roleList);
        }
        if (roleList == null) {
            roleList = new String[0];
        }
        if (claims == null) {
            claims = new HashMap<String,String>();
        }
        // #################### <Listeners> #####################################################
        for (UserStoreManagerListener listener : UMListenerServiceComponent
                .getUserStoreManagerListeners()) {
            if (!listener.addUser(userName, credential, roleList, claims, profileName, this)) {
                return;
            }
        }
        // String buffers are used to let listeners to modify passwords
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (credential == null) { // a default password will be set
                StringBuffer credBuff = new StringBuffer();
                if (!listener.doPreAddUser(userName, credBuff, roleList, claims, profileName,
                        this)) {
                    return;
                }
                credential = credBuff.toString(); // reading the modified value
            } else if (credential instanceof String) {
                StringBuffer credBuff = new StringBuffer((String) credential);
                if (!listener.doPreAddUser(userName, credBuff, roleList, claims, profileName,
                        this)) {
                    return;
                }
                credential = credBuff.toString(); // reading the modified value
            }
        }
        // #################### </Listeners> #####################################################

        if (!checkUserNameValid(userStore.getDomainFreeName())) {
            String message = "Username " + userStore.getDomainFreeName() + " is not valid. User name must be a non null string with following format, ";
            String regEx = realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX);
            throw new UserStoreException(message + regEx);
        }

        if (!checkUserPasswordValid(credential)) {
            String message = "Credential not valid. Credential must be a non null string with following format, ";
            String regEx = realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX);
            throw new UserStoreException(message + regEx);
        }

        if (doCheckExistingUser(userStore.getDomainFreeName())) {
            throw new UserStoreException(EXISTING_USER + "Username '" + userName
                    + "' already exists in the system. Please pick another username.");
        }


        List<String> internalRoles = new ArrayList<String>();
        List<String> externalRoles = new ArrayList<String>();
        int index;
        if (roleList != null) {
            for (String role : roleList) {
                if (role != null && role.trim().length() > 0) {
                    index = role.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
                    if (index > 0) {
                        String domain = role.substring(0, index);
                        if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)) {
                            internalRoles.add(UserCoreUtil.removeDomainFromName(role));
                            continue;
                        } else if (APPLICATION_DOMAIN.equalsIgnoreCase(domain) ||
                                WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
                            internalRoles.add(role);
                            continue;
                        }
                    }
                    externalRoles.add(UserCoreUtil.removeDomainFromName(role));
                }
            }
        }

        // check existance of roles and claims before user is adding
        for (String internalRole : internalRoles) {
            if (!hybridRoleManager.isExistingRole(internalRole)) {
                throw new UserStoreException("Internal role is not exist : " + internalRole);
            }
        }

        for (String externalRole : externalRoles) {
            if (!doCheckExistingRole(externalRole)) {
                throw new UserStoreException("External role is not exist : " + externalRole);
            }
        }

        if (claims != null) {
            for (Map.Entry<String, String> entry : claims.entrySet()) {
                ClaimMapping claimMapping = null;
                try {
                    claimMapping = (ClaimMapping) claimManager.getClaimMapping(entry.getKey());
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    String errorMessage = "Error in obtaining claim mapping for persisting user attributes.";
                    throw new UserStoreException(errorMessage, e);
                }
                if (claimMapping == null) {
                    String errorMessage = INVALID_CLAIM_URL + " Invalid claim uri has been provided.";
                    throw new UserStoreException(errorMessage);
                }
            }
        }

        doAddUser(userName, credential, externalRoles.toArray(new String[externalRoles.size()]),
                claims, profileName, requirePasswordChange);

        if (internalRoles.size() > 0) {
            hybridRoleManager.updateHybridRoleListOfUser(userName, null,
                    internalRoles.toArray(new String[internalRoles.size()]));
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostAddUser(userName, credential, roleList, claims, profileName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        try {
            roleList = UserCoreUtil
                    .combine(doGetInternalRoleListOfUser(userName, "*"), Arrays.asList(roleList));
            // If the newly created user has internal roles assigned from the UI wizard those internal roles
            // will be duplicated in the roles list. Duplcated roles are eliminated here.
            Set<String> rolesSet = new HashSet<String>(Arrays.asList(roleList));
            roleList = new String[rolesSet.size()];
            rolesSet.toArray(roleList);
            addToUserRolesCache(tenantId, userName, roleList);
        } catch (Exception e) {
            //if adding newly created user's roles to the user roles cache fails, do nothing. It will read
            //from the database upon updating user.
        }
    }

    /**
     * {@inheritDoc}
     */
    public void addUser(String userName, Object credential, String[] roleList,
                        Map<String, String> claims, String profileName) throws UserStoreException {
        this.addUser(userName, credential, roleList, claims, profileName, false);
    }

    public final void updateUserListOfRole(final String roleName, final String[] deletedUsers, final String[] newUsers)
            throws UserStoreException {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<String>() {
                public String run() throws Exception {
                    updateUserListOfRoleInternal(roleName, deletedUsers, newUsers);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }
    }

    /**
     * {@inheritDoc}
     */
    private final void updateUserListOfRoleInternal(String roleName, String[] deletedUsers, String[] newUsers)
            throws UserStoreException {

        String primaryDomain = getMyDomainName();
        if (primaryDomain != null) {
            primaryDomain += CarbonConstants.DOMAIN_SEPARATOR;
        }

        if (deletedUsers != null && deletedUsers.length > 0) {
            Arrays.sort(deletedUsers);
            // Updating the user list of a role belong to the primary domain.
            if (UserCoreUtil.isPrimaryAdminRole(roleName, realmConfig)) {
                for (int i = 0; i < deletedUsers.length; i++) {
                    if (deletedUsers[i].equalsIgnoreCase(realmConfig.getAdminUserName())
                            || (primaryDomain + deletedUsers[i]).equalsIgnoreCase(realmConfig
                            .getAdminUserName())) {
                        throw new UserStoreException(REMOVE_ADMIN_USER + " Cannot remove Admin user from Admin role");
                    }

                }
            }
        }

        UserStore userStore = getUserStore(roleName);

        if (userStore.isHybridRole()) {
            // Check whether someone is trying to update Everyone role.
            if (UserCoreUtil.isEveryoneRole(roleName, realmConfig)) {
                throw new UserStoreException("Cannot update everyone role");
            }

            if(UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStore.getDomainName())) {
                hybridRoleManager.updateUserListOfHybridRole(userStore.getDomainFreeName(),
                        deletedUsers, newUsers);
            } else {
                hybridRoleManager.updateUserListOfHybridRole(userStore.getDomainAwareName(),
                        deletedUsers, newUsers);
            }
            clearUserRolesCacheByTenant(this.tenantId);
            return;
        }

        if (userStore.isSystemStore()) {
            systemUserRoleManager.updateUserListOfSystemRole(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromNames(deletedUsers),
                    UserCoreUtil.removeDomainFromNames(newUsers));
            return;
        }

        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().updateUserListOfRole(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromNames(deletedUsers),
                    UserCoreUtil.removeDomainFromNames(newUsers));
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################
        if (deletedUsers == null) {
            deletedUsers = new String[0];
        }
        if (newUsers == null) {
            newUsers = new String[0];
        }
        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreUpdateUserListOfRole(roleName, deletedUsers,
                    newUsers, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        if ((deletedUsers != null && deletedUsers.length > 0)
                || (newUsers != null && newUsers.length > 0)) {
            if (!isReadOnly() && writeGroupsEnabled) {
                doUpdateUserListOfRole(userStore.getDomainFreeName(),
                        UserCoreUtil.removeDomainFromNames(deletedUsers),
                        UserCoreUtil.removeDomainFromNames(newUsers));
            } else {
                throw new UserStoreException(
                        "Read-only user store.Roles cannot be added or modified");
            }
        }

        // need to clear user roles cache upon roles update
        clearUserRolesCacheByTenant(this.tenantId);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostUpdateUserListOfRole(roleName, deletedUsers,
                    newUsers, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    public final void updateRoleListOfUser(final String roleName, final String[] deletedUsers, final String[] newRoles)
            throws UserStoreException {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<String>() {
                public String run() throws Exception {
                    updateRoleListOfUserInternal(roleName, deletedUsers, newRoles);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }
    }

    /**
     * {@inheritDoc}
     */
    private final void updateRoleListOfUserInternal(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {

        String primaryDomain = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        if (primaryDomain != null) {
            primaryDomain += CarbonConstants.DOMAIN_SEPARATOR;
        }

        if (deletedRoles != null && deletedRoles.length > 0) {
            Arrays.sort(deletedRoles);
            if (UserCoreUtil.isPrimaryAdminUser(userName, realmConfig)) {
                for (int i = 0; i < deletedRoles.length; i++) {
                    if (deletedRoles[i].equalsIgnoreCase(realmConfig.getAdminRoleName())
                            || (primaryDomain + deletedRoles[i]).equalsIgnoreCase(realmConfig
                            .getAdminRoleName())) {
                        throw new UserStoreException("Cannot remove Admin user from Admin role");
                    }
                }
            }
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().updateRoleListOfUser(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromNames(deletedRoles),
                    UserCoreUtil.removeDomainFromNames(newRoles));
            return;
        }

        if (userStore.isSystemStore()) {
            systemUserRoleManager.updateSystemRoleListOfUser(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromNames(deletedRoles),
                    UserCoreUtil.removeDomainFromNames(newRoles));
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################
        if (deletedRoles == null) {
            deletedRoles = new String[0];
        }
        if (newRoles == null) {
            newRoles = new String[0];
        }
        // This happens only once during first startup - adding administrator user/role.
        if (userName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
            userName = userStore.getDomainFreeName();
            deletedRoles = UserCoreUtil.removeDomainFromNames(deletedRoles);
            newRoles = UserCoreUtil.removeDomainFromNames(newRoles);
        }

        List<String> internalRoleDel = new ArrayList<String>();
        List<String> internalRoleNew = new ArrayList<String>();

        List<String> roleDel = new ArrayList<String>();
        List<String> roleNew = new ArrayList<String>();

        if (deletedRoles != null && deletedRoles.length > 0) {
            for (String deleteRole : deletedRoles) {
                if (UserCoreUtil.isEveryoneRole(deleteRole, realmConfig)) {
                    throw new UserStoreException("Everyone role cannot be updated");
                }
                String domain = null;
                int index1 = deleteRole.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
                if (index1 > 0) {
                    domain = deleteRole.substring(0, index1);
                }
                if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain) || this.isReadOnly()) {
                    internalRoleDel.add(UserCoreUtil.removeDomainFromName(deleteRole));
                } else if (APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
                    internalRoleDel.add(deleteRole);
                } else {
                    // This is domain free role name.
                    roleDel.add(UserCoreUtil.removeDomainFromName(deleteRole));
                }
            }
            deletedRoles = roleDel.toArray(new String[roleDel.size()]);
        }

        if (newRoles != null && newRoles.length > 0) {
            for (String newRole : newRoles) {
                if (UserCoreUtil.isEveryoneRole(newRole, realmConfig)) {
                    throw new UserStoreException("Everyone role cannot be updated");
                }
                String domain = null;
                int index2 = newRole.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
                if (index2 > 0) {
                    domain = newRole.substring(0, index2);
                }
                if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain) || this.isReadOnly()) {
                    internalRoleNew.add(UserCoreUtil.removeDomainFromName(newRole));
                } else if (APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
                    internalRoleNew.add(newRole);
                } else {
                    roleNew.add(UserCoreUtil.removeDomainFromName(newRole));
                }
            }
            newRoles = roleNew.toArray(new String[roleNew.size()]);
        }

        if (internalRoleDel.size() > 0 || internalRoleNew.size() > 0) {
            hybridRoleManager.updateHybridRoleListOfUser(userStore.getDomainFreeName(),
                    internalRoleDel.toArray(new String[internalRoleDel.size()]),
                    internalRoleNew.toArray(new String[internalRoleNew.size()]));
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreUpdateRoleListOfUser(userName, deletedRoles, newRoles, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        if ((deletedRoles != null && deletedRoles.length > 0)
                || (newRoles != null && newRoles.length > 0)) {
            if (!isReadOnly() && writeGroupsEnabled) {
                doUpdateRoleListOfUser(userName, deletedRoles, newRoles);
            } else {
                throw new UserStoreException("Read-only user store. Cannot add/modify roles.");
            }
        }

        clearUserRolesCache(UserCoreUtil.addDomainToName(userName, getMyDomainName()));

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostUpdateRoleListOfUser(userName, deletedRoles, newRoles, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * {@inheritDoc}
     */
    public final void updateRoleName(String roleName, String newRoleName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class};
            callSecure("updateRoleName", new Object[]{roleName, newRoleName}, argTypes);
            return;
        }

        if (UserCoreUtil.isPrimaryAdminRole(newRoleName, realmConfig)) {
            throw new UserStoreException("Cannot rename admin role");
        }

        if (UserCoreUtil.isEveryoneRole(newRoleName, realmConfig)) {
            throw new UserStoreException("Cannot rename everyone role");
        }

        UserStore userStore = getUserStore(roleName);
        UserStore userStoreNew = getUserStore(newRoleName);

        if (!UserCoreUtil.canRoleBeRenamed(userStore, userStoreNew, realmConfig)) {
            throw new UserStoreException("The role cannot be renamed");
        }

        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().updateRoleName(userStore.getDomainFreeName(),
                    userStoreNew.getDomainFreeName());
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (userStore.isHybridRole()) {
            if(UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStore.getDomainName())) {
                hybridRoleManager.updateHybridRoleName(userStore.getDomainFreeName(),
                        userStoreNew.getDomainFreeName());
            } else {
                hybridRoleManager.updateHybridRoleName(userStore.getDomainAwareName(),
                        userStoreNew.getDomainAwareName());
            }

            // This is a special case. We need to pass roles with domains.
            userRealm.getAuthorizationManager().resetPermissionOnUpdateRole(
                    userStore.getDomainAwareName(), userStoreNew.getDomainAwareName());

            // Need to update user role cache upon update of role names
            clearUserRolesCacheByTenant(this.tenantId);
            return;
        }
//
//		RoleContext ctx = createRoleContext(roleName);
//        if (isOthersSharedRole(roleName)) {          // TODO do we need this
//            throw new UserStoreException(
//                    "Logged in user doesn't have permission to delete a role belong to other tenant");
//        }

        if (isExistingRole(newRoleName)) {
            throw new UserStoreException("Role name: " + newRoleName
                    + " in the system. Please pick another role name.");
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreUpdateRoleName(roleName, newRoleName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        if (!isReadOnly() && writeGroupsEnabled) {
            doUpdateRoleName(userStore.getDomainFreeName(), userStoreNew.getDomainFreeName());
        } else {
            throw new UserStoreException(
                    READ_ONLY_STORE + " Read-only UserStoreManager. Roles cannot be added or modified.");
        }

        // This is a special case. We need to pass domain aware name.
        userRealm.getAuthorizationManager().resetPermissionOnUpdateRole(
                userStore.getDomainAwareName(), userStoreNew.getDomainAwareName());

        // need to update user role cache upon update of role names
        clearUserRolesCacheByTenant(tenantId);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostUpdateRoleName(roleName, newRoleName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }

    /**
     * TODO  move to API
     *
     * @param roleName
     * @param deletedUsers
     * @param newUsers
     * @throws UserStoreException
     */
    public void updateUsersOfSharedRole(String roleName,
                                        String[] deletedUsers, String[] newUsers) throws UserStoreException {

        UserStoreManager manager = getUserStoreWithSharedRoles();

        if (manager == null) {
            throw new UserStoreException("Share Groups are not supported by this realm");
        }

        ((MongoDBUserStoreManager) manager).doUpdateUserListOfRole(roleName, deletedUsers, newUsers);
    }

    /**
     * TODO move to API
     *
     * @return
     * @throws UserStoreException
     */
    public String[] getSharedRolesOfUser(String userName,
                                         String tenantDomain, String filter) throws UserStoreException {

        UserStore userStore = getUserStore(userName);
        UserStoreManager manager = userStore.getUserStoreManager();

        if (!((MongoDBUserStoreManager) manager).isSharedGroupEnabled()) {
            throw new UserStoreException("Share Groups are not supported by user store");
        }

        String[] sharedRoles = ((MongoDBUserStoreManager) manager).
                doGetSharedRoleListOfUser(userStore.getDomainFreeName(), tenantDomain, filter);
        return UserCoreUtil.removeDomainFromNames(sharedRoles);
    }

    /**
     * TODO move to API
     *
     * @return
     * @throws UserStoreException
     */
    public String[] getUsersOfSharedRole(String roleName, String filter) throws UserStoreException {

        UserStoreManager manager = getUserStoreWithSharedRoles();

        if (manager == null) {
            throw new UserStoreException("Share Groups are not supported by this realm");
        }

        String[] users = ((MongoDBUserStoreManager) manager).doGetUserListOfRole(roleName, filter);
        return UserCoreUtil.removeDomainFromNames(users);
    }

    /**
     * TODO move to API
     *
     * @return
     * @throws UserStoreException
     */
    public String[] getSharedRoleNames(String tenantDomain, String filter,
                                       int maxItemLimit) throws UserStoreException {


        UserStoreManager manager = getUserStoreWithSharedRoles();

        if (manager == null) {
            throw new UserStoreException("Share Groups are not supported by this realm");
        }

        String[] sharedRoles = null;
        try {
            sharedRoles = ((MongoDBUserStoreManager) manager).
                    doGetSharedRoleNames(tenantDomain, filter, maxItemLimit);
        } catch (UserStoreException e) {
            throw new UserStoreException("Error while retrieving shared roles", e);
        }
        return UserCoreUtil.removeDomainFromNames(sharedRoles);
    }

    /**
     * TODO move to API
     *
     * @return
     * @throws UserStoreException
     */
    public String[] getSharedRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        UserStoreManager manager = getUserStoreWithSharedRoles();

        if (manager == null) {
            throw new UserStoreException("Share Groups are not supported by this realm");
        }

        String[] sharedRoles = null;
        try {
            sharedRoles = ((MongoDBUserStoreManager) manager).
                    doGetSharedRoleNames(null, filter, maxItemLimit);
        } catch (UserStoreException e) {
            throw new UserStoreException("Error while retrieving shared roles", e);
        }
        return UserCoreUtil.removeDomainFromNames(sharedRoles);
    }


    public void addInternalRole(String roleName, String[] userList,
                                org.wso2.carbon.user.api.Permission[] permission) throws UserStoreException {
        doAddInternalRole(roleName, userList, permission);
    }

    private UserStoreManager getUserStoreWithSharedRoles() throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{};
            Object object = callSecure("getUserStoreWithSharedRoles", new Object[]{}, argTypes);
            return (UserStoreManager) object;
        }

        UserStoreManager sharedRoleManager = null;

        if (isSharedGroupEnabled()) {
            return this;
        }

        for (Map.Entry<String, UserStoreManager> entry : userStoreManagerHolder.entrySet()) {
            UserStoreManager manager = entry.getValue();
            if (manager != null && ((MongoDBUserStoreManager) manager).isSharedGroupEnabled()) {
                if (sharedRoleManager != null) {
                    throw new UserStoreException("There can not be more than one user store that support" +
                            "shared groups");
                }
                sharedRoleManager = manager;
            }
        }

        return sharedRoleManager;
    }

    /**
     * TODO move to API
     *
     * @param userName
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public boolean isUserInRole(String userName, String roleName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class};
            Object object = callSecure("isUserInRole", new Object[]{userName, roleName}, argTypes);
            return (Boolean) object;
        }

        if (roleName == null || roleName.trim().length() == 0 || userName == null ||
                userName.trim().length() == 0) {
            return false;
        }

        // anonymous user is always assigned to  anonymous role
        if (CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equalsIgnoreCase(roleName) &&
                CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equalsIgnoreCase(userName)) {
            return true;
        }

        if (!CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equalsIgnoreCase(userName) &&
                realmConfig.getEveryOneRoleName().equalsIgnoreCase(roleName) &&
                !systemUserRoleManager.isExistingSystemUser(UserCoreUtil.
                        removeDomainFromName(userName))) {
            return true;
        }


        String[] roles = null;

        roles = getRoleListOfUserFromCache(tenantId, userName);
        if (roles != null && roles.length > 0) {
            if (UserCoreUtil.isContain(roleName, roles)) {
                return true;
            }
        }

        // TODO create new cache for this method
        String modifiedUserName = UserCoreConstants.IS_USER_IN_ROLE_CACHE_IDENTIFIER + userName;
        roles = getRoleListOfUserFromCache(tenantId, modifiedUserName);
        if (roles != null && roles.length > 0) {
            if (UserCoreUtil.isContain(roleName, roles)) {
                return true;
            }
        }

        if (UserCoreConstants.INTERNAL_DOMAIN.
                equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleName))
                || APPLICATION_DOMAIN.equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleName)) ||
                WORKFLOW_DOMAIN.equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleName))) {

            String[] internalRoles = doGetInternalRoleListOfUser(userName, "*");
            if (UserCoreUtil.isContain(roleName, internalRoles)) {
                addToIsUserHasRole(modifiedUserName, roleName, roles);
                return true;
            }
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()
                && (userStore.getUserStoreManager() instanceof MongoDBUserStoreManager)) {
            return ((MongoDBUserStoreManager) userStore.getUserStoreManager()).isUserInRole(
                    userStore.getDomainFreeName(), roleName);
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (userStore.isSystemStore()) {
            return systemUserRoleManager.isUserInRole(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromName(roleName));
        }
        // admin user is always assigned to admin role if it is in primary user store
        if (realmConfig.isPrimary() && roleName.equalsIgnoreCase(realmConfig.getAdminRoleName()) &&
                userName.equalsIgnoreCase(realmConfig.getAdminUserName())) {
            return true;
        }

        String roleDomainName = UserCoreUtil.extractDomainFromName(roleName);

        String roleDomainNameForForest = realmConfig.
                getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_GROUP_SEARCH_DOMAINS);
        if (roleDomainNameForForest != null && roleDomainNameForForest.trim().length() > 0) {
            String[] values = roleDomainNameForForest.split("#");
            for (String value : values) {
                if (value != null && !value.trim().equalsIgnoreCase(roleDomainName)) {
                    return false;
                }
            }
        } else if (!userStore.getDomainName().equalsIgnoreCase(roleDomainName)) {
            return false;
        }

        boolean success = false;
        if (readGroupsEnabled) {
            success = doCheckIsUserInRole(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromName(roleName));
        }

        // add to cache
        if (success) {
            addToIsUserHasRole(modifiedUserName, roleName, roles);
        }
        return success;
    }

    /**
     * Helper method
     *
     * @param userName
     * @param roleName
     * @param currentRoles
     */
    private void addToIsUserHasRole(String userName, String roleName, String[] currentRoles) {
        List<String> roles;
        if (currentRoles != null) {
            roles = new ArrayList<String>(Arrays.asList(currentRoles));
        } else {
            roles = new ArrayList<String>();
        }
        roles.add(roleName);
        addToUserRolesCache(tenantId, userName, roles.toArray(new String[roles.size()]));
    }

    //////////////////////////////////// Shared role APIs finish //////////////////////////////////////////

    /**
     * {@inheritDoc}
     */
    public boolean isExistingUser(String userName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            Object object = callSecure("isExistingUser", new Object[]{userName}, argTypes);
            return (Boolean) object;
        }

        if (UserCoreUtil.isRegistrySystemUser(userName)) {
            return true;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().isExistingUser(userStore.getDomainFreeName());
        }

        // #################### Domain Name Free Zone Starts Here ################################

        if (userStore.isSystemStore()) {
            return systemUserRoleManager.isExistingSystemUser(userStore.getDomainFreeName());
        }


        return doCheckExistingUser(userStore.getDomainFreeName());

    }


    /**
     * {@inheritDoc}
     */
    public final String[] listUsers(String filter, int maxItemLimit) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, int.class};
            Object object = callSecure("listUsers", new Object[]{filter, maxItemLimit}, argTypes);
            return (String[]) object;
        }

        int index;
        index = filter.indexOf(CarbonConstants.DOMAIN_SEPARATOR);

        // Check whether we have a secondary UserStoreManager setup.
        if (index > 0) {
            // Using the short-circuit. User name comes with the domain name.
            String domain = filter.substring(0, index);

            UserStoreManager secManager = getSecondaryUserStoreManager(domain);
            if (secManager != null) {
                // We have a secondary UserStoreManager registered for this domain.
                filter = filter.substring(index + 1);
                if (secManager instanceof MongoDBUserStoreManager) {
                    return ((MongoDBUserStoreManager) secManager)
                            .doListUsers(filter, maxItemLimit);
                } else {
                    return secManager.listUsers(filter, maxItemLimit);
                }
            } else {
                // Exception is not need to as listing of users
                // throw new UserStoreException("Invalid Domain Name");
            }
        } else if (index == 0) {
            return doListUsers(filter.substring(index + 1), maxItemLimit);
        }

        String[] userList = doListUsers(filter, maxItemLimit);

        String primaryDomain = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        if (this.getSecondaryUserStoreManager() != null) {
            for (Map.Entry<String, UserStoreManager> entry : userStoreManagerHolder.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(primaryDomain)) {
                    continue;
                }
                UserStoreManager storeManager = entry.getValue();
                if (storeManager instanceof MongoDBUserStoreManager) {
                    try {
                        String[] secondUserList = ((MongoDBUserStoreManager) storeManager)
                                .doListUsers(filter, maxItemLimit);
                        userList = UserCoreUtil.combineArrays(userList, secondUserList);
                    } catch (UserStoreException ex) {
                        // We can ignore and proceed. Ignore the results from this user store.
                        log.error(ex);
                    }
                } else {
                    String[] secondUserList = storeManager.listUsers(filter, maxItemLimit);
                    userList = UserCoreUtil.combineArrays(userList, secondUserList);
                }
            }
        }

        return userList;
    }

    /**
     * {@inheritDoc}
     */
    public final String[] getUserListOfRole(String roleName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            Object object = callSecure("getUserListOfRole", new Object[]{roleName}, argTypes);
            return (String[]) object;
        }

        String[] userNames = new String[0];

        // If role does not exit, just return
        if (!isExistingRole(roleName)) {
            return userNames;
        }

        UserStore userStore = getUserStore(roleName);

        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().getUserListOfRole(userStore.getDomainFreeName());
        }


        // #################### Domain Name Free Zone Starts Here
        // ################################

        if (userStore.isSystemStore()) {
            return systemUserRoleManager.getUserListOfSystemRole(userStore.getDomainFreeName());
        }

        String[] userNamesInHybrid = new String[0];
        if (userStore.isHybridRole()) {
            if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStore.getDomainName())) {
                userNamesInHybrid =
                        hybridRoleManager.getUserListOfHybridRole(userStore.getDomainFreeName());
            } else {
                userNamesInHybrid = hybridRoleManager.getUserListOfHybridRole(userStore.getDomainAwareName());
            }

            // remove domain
            List<String> finalNameList = new ArrayList<String>();
            String displayNameAttribute =
                    this.realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);

            if (userNamesInHybrid != null && userNamesInHybrid.length > 0) {
                if (displayNameAttribute != null && displayNameAttribute.trim().length() > 0) {
                    for (String userName : userNamesInHybrid) {
                        String domainName = UserCoreUtil.extractDomainFromName(userName);
                        if (domainName == null || domainName.trim().length() == 0) {
                            finalNameList.add(userName);
                        }
                        UserStoreManager userManager = userStoreManagerHolder.get(domainName);
                        userName = UserCoreUtil.removeDomainFromName(userName);
                        if (userManager != null) {
                            String[] displayNames = null;
                            if (userManager instanceof MongoDBUserStoreManager) {
                                // get displayNames
                                displayNames = ((MongoDBUserStoreManager) userManager)
                                        .doGetDisplayNamesForInternalRole(new String[]{userName});
                            } else {
                                displayNames = userManager.getRoleNames();
                            }

                            for (String displayName : displayNames) {
                                // if domain names are not added by above method, add it
                                // here
                                String nameWithDomain = UserCoreUtil.addDomainToName(displayName, domainName);
                                finalNameList.add(nameWithDomain);
                            }
                        }
                    }
                } else {
                    return userNamesInHybrid;
                }
            }
            return finalNameList.toArray(new String[finalNameList.size()]);
            // return
            // hybridRoleManager.getUserListOfHybridRole(userStore.getDomainFreeName());
        }

        if (readGroupsEnabled) {
            userNames = doGetUserListOfRole(roleName, "*");
        }

        return userNames;
    }

    public String[] getRoleListOfUser(String userName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            Object object = callSecure("getRoleListOfUser", new Object[]{userName}, argTypes);
            return (String[]) object;
        }

        String[] roleNames = null;


        // anonymous user is only assigned to  anonymous role
        if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equalsIgnoreCase(userName)) {
            return new String[]{CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME};
        }

        // Check whether roles exist in cache
        roleNames = getRoleListOfUserFromCache(this.tenantId, userName);
        if (roleNames != null && roleNames.length > 0) {
            return roleNames;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().getRoleListOfUser(userStore.getDomainFreeName());
        }

        if (userStore.isSystemStore()) {
            return systemUserRoleManager.getSystemRoleListOfUser(userStore.getDomainFreeName());
        }
        // #################### Domain Name Free Zone Starts Here ################################

        roleNames = doGetRoleListOfUser(userName, "*");

        return roleNames;

    }

    /**
     * Getter method for claim manager property specifically to be used in the implementations of
     * UserOperationEventListener implementations
     *
     * @return
     */
    public ClaimManager getClaimManager() {
        return claimManager;
    }

    /**
     *
     */
    public void addRole(String roleName, String[] userList,
                        org.wso2.carbon.user.api.Permission[] permissions, boolean isSharedRole)
            throws org.wso2.carbon.user.api.UserStoreException {

        UserStore userStore = getUserStore(roleName);

        if (isSharedRole && !isSharedGroupEnabled()) {
            throw new org.wso2.carbon.user.api.UserStoreException(
                    SHARED_USER_ROLES + "User store doesn't support shared user roles functionality");
        }

        if (userStore.isHybridRole()) {
            doAddInternalRole(roleName, userList, permissions);
            return;
        }

        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().addRole(userStore.getDomainFreeName(),
                    UserCoreUtil.removeDomainFromNames(userList), permissions, isSharedRole);
            return;
        }

        // #################### Domain Name Free Zone Starts Here ################################
        if (userList == null) {
            userList = new String[0];
        }
        if (permissions == null) {
            permissions = new org.wso2.carbon.user.api.Permission[0];
        }
        // This happens only once during first startup - adding administrator user/role.
        if (roleName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
            roleName = userStore.getDomainFreeName();
            userList = UserCoreUtil.removeDomainFromNames(userList);
        }


        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreAddRole(roleName, userList, permissions, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        // Check for validations
        if (isReadOnly()) {
            throw new UserStoreException(
                    READ_ONLY_PRIMARY_STORE + " Cannot add role to Read Only user store unless it is primary");
        }

        if (!isRoleNameValid(roleName)) {
            String regEx = realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
            throw new UserStoreException(
                    INVALID_ROLE + " Role name not valid. Role name must be a non null string with following format, "
                            + regEx);
        }

        if (doCheckExistingRole(roleName)) {
            throw new UserStoreException(EXISTING_ROLE+ " Role name: " + roleName +
                    " in the system. Please pick another role name.");
        }

        String roleWithDomain = null;
        if (!isReadOnly() && writeGroupsEnabled) {
            // add role in to actual user store
            doAddRole(roleName, userList, isSharedRole);

            roleWithDomain = UserCoreUtil.addDomainToName(roleName, getMyDomainName());
        } else {
            throw new UserStoreException(
                    NO_READ_WRITE_PERMISSIONS + " Role cannot be added. User store is read only or cannot write groups.");
        }

        // add permission in to the the permission store
        if (permissions != null) {
            for (org.wso2.carbon.user.api.Permission permission : permissions) {
                String resourceId = permission.getResourceId();
                String action = permission.getAction();
                if (resourceId == null || resourceId.trim().length() == 0) {
                    continue;
                }

                if (action == null || action.trim().length() == 0) {
                    // default action value // TODO
                    action = "read";
                }
                // This is a special case. We need to pass domain aware name.
                userRealm.getAuthorizationManager().authorizeRole(roleWithDomain, resourceId,
                        action);
            }
        }

        // if existing users are added to role, need to update user role cache
        if ((userList != null) && (userList.length > 0)) {
            clearUserRolesCacheByTenant(tenantId);
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostAddRole(roleName, userList, permissions, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }


    /**
     * TODO move to API
     *
     * @return
     */
    public boolean isSharedGroupEnabled() {
        String value = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.SHARED_GROUPS_ENABLED);
        try {
            return realmConfig.isPrimary() && !isReadOnly() && TRUE_VALUE.equalsIgnoreCase(value);
        } catch (UserStoreException e) {
            log.error(e);
        }
        return false;
    }

    /**
     * Removes the shared roles relevant to the provided tenant domain
     *
     * @param sharedRoles
     * @param tenantDomain
     */
    protected void filterSharedRoles(List<String> sharedRoles, String tenantDomain) {
        if (tenantDomain != null) {
            for (Iterator<String> i = sharedRoles.iterator(); i.hasNext(); ) {
                String role = i.next();
                if (role.indexOf(tenantDomain) > -1) {
                    i.remove();
                }
            }
        }
    }

    /**
     * Delete the role with the given role name
     *
     * @param roleName The role name
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    public final void deleteRole(String roleName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            callSecure("deleteRole", new Object[]{roleName}, argTypes);
            return;
        }

        if (UserCoreUtil.isPrimaryAdminRole(roleName, realmConfig)) {
            throw new UserStoreException("Cannot delete admin role");
        }
        if (UserCoreUtil.isEveryoneRole(roleName, realmConfig)) {
            throw new UserStoreException("Cannot delete everyone role");
        }

        UserStore userStore = getUserStore(roleName);
        if (userStore.isRecurssive()) {
            userStore.getUserStoreManager().deleteRole(userStore.getDomainFreeName());
            return;
        }

        String roleWithDomain = UserCoreUtil.addDomainToName(roleName, getMyDomainName());
        // #################### Domain Name Free Zone Starts Here ################################

        if (userStore.isHybridRole()) {
            if (APPLICATION_DOMAIN.equalsIgnoreCase(userStore.getDomainName()) ||
                    WORKFLOW_DOMAIN.equalsIgnoreCase(userStore.getDomainName())) {
                hybridRoleManager.deleteHybridRole(roleName);
            } else {
                hybridRoleManager.deleteHybridRole(userStore.getDomainFreeName());
            }
            clearUserRolesCacheByTenant(tenantId);
            return;
        }
//
//		RoleContext ctx = createRoleContext(roleName);
//		if (isOthersSharedRole(roleName)) {
//			throw new UserStoreException(
//			                             "Logged in user doesn't have permission to delete a role belong to other tenant");
//		}


        if (!doCheckExistingRole(roleName)) {
            throw new UserStoreException("Can not delete non exiting role");
        }

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPreDeleteRole(roleName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

        if (!isReadOnly() && writeGroupsEnabled) {
            doDeleteRole(roleName);
        } else {
            throw new UserStoreException(
                    "Role cannot be deleted. User store is read only or cannot write groups.");
        }

        // clear role authorization
        userRealm.getAuthorizationManager().clearRoleAuthorization(roleWithDomain);

        // clear cache
        clearUserRolesCacheByTenant(tenantId);

        // #################### <Listeners> #####################################################
        for (UserOperationEventListener listener : UMListenerServiceComponent
                .getUserOperationEventListeners()) {
            if (!listener.doPostDeleteRole(roleName, this)) {
                return;
            }
        }
        // #################### </Listeners> #####################################################

    }


    /**
     * Method to get the password expiration time.
     *
     * @param userName the user name.
     *
     * @return the password expiration time.
     * @throws UserStoreException throw if the operation failed.
     */

    public Date getPasswordExpirationTime(String userName) throws UserStoreException {
        UserStore userStore = getUserStore(userName);

        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().getPasswordExpirationTime(userStore.getDomainFreeName());
        }

        return null;
    }

    private UserStore getUserStore(final String user) throws UserStoreException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<UserStore>() {
                public UserStore run() throws Exception {
                    return getUserStoreInternal(user);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }
    }

    /**
     * @return
     * @throws UserStoreException
     */
    private UserStore getUserStoreInternal(String user) throws UserStoreException {

        int index;
        index = user.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
        UserStore userStore = new UserStore();
        String domainFreeName = null;

        // Check whether we have a secondary UserStoreManager setup.
        if (index > 0) {
            // Using the short-circuit. User name comes with the domain name.
            String domain = user.substring(0, index);
            UserStoreManager secManager = getSecondaryUserStoreManager(domain);
            domainFreeName = user.substring(index + 1);

            if (secManager != null) {
                userStore.setUserStoreManager(secManager);
                userStore.setDomainAwareName(user);
                userStore.setDomainFreeName(domainFreeName);
                userStore.setDomainName(domain);
                userStore.setRecurssive(true);
                return userStore;
            } else {
                if (!domain.equalsIgnoreCase(getMyDomainName())) {
                    if ((UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)
                            || APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain))) {
                        userStore.setHybridRole(true);
                    } else if (UserCoreConstants.SYSTEM_DOMAIN_NAME.equalsIgnoreCase(domain)) {
                        userStore.setSystemStore(true);
                    } else {
                        throw new UserStoreException("Invalid Domain Name");
                    }
                }

                userStore.setDomainAwareName(user);
                userStore.setDomainFreeName(domainFreeName);
                userStore.setDomainName(domain);
                userStore.setRecurssive(false);
                return userStore;
            }
        }

        String domain = getMyDomainName();
        userStore.setUserStoreManager(this);
        if (index > 0) {
            userStore.setDomainAwareName(user);
            userStore.setDomainFreeName(domainFreeName);
        } else {
            userStore.setDomainAwareName(domain + CarbonConstants.DOMAIN_SEPARATOR + user);
            userStore.setDomainFreeName(user);
        }
        userStore.setRecurssive(false);
        userStore.setDomainName(domain);

        return userStore;
    }

    /**
     * {@inheritDoc}
     */
    public final UserStoreManager getSecondaryUserStoreManager() {
        return secondaryUserStoreManager;
    }

    /**
     *
     */
    public final void setSecondaryUserStoreManager(UserStoreManager secondaryUserStoreManager) {
        this.secondaryUserStoreManager = secondaryUserStoreManager;
    }

    /**
     * {@inheritDoc}
     */
    public final UserStoreManager getSecondaryUserStoreManager(String userDomain) {
        if (userDomain == null) {
            return null;
        }
        return userStoreManagerHolder.get(userDomain.toUpperCase());
    }

    /**
     * {@inheritDoc}
     */
    public final void addSecondaryUserStoreManager(String userDomain,
                                                   UserStoreManager userStoreManager) {
        if (userDomain != null) {
            userStoreManagerHolder.put(userDomain.toUpperCase(), userStoreManager);
        }
    }

    public final void clearAllSecondaryUserStores() {
        userStoreManagerHolder.clear();

        if (getMyDomainName() != null) {
            userStoreManagerHolder.put(getMyDomainName().toUpperCase(), this);
        }
    }

    /**
     * {@inheritDoc}
     */
    public final String[] getAllSecondaryRoles() throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{};
            Object object = callSecure("getAllSecondaryRoles", new Object[]{}, argTypes);
            return (String[]) object;
        }

        UserStoreManager secondary = this.getSecondaryUserStoreManager();
        List<String> roleList = new ArrayList<String>();
        while (secondary != null) {
            String[] roles = secondary.getRoleNames(true);
            if (roles != null && roles.length > 0) {
                Collections.addAll(roleList, roles);
            }
            secondary = secondary.getSecondaryUserStoreManager();
        }
        return roleList.toArray(new String[roleList.size()]);
    }

    /**
     * @return
     */
    public boolean isSCIMEnabled() {
        String scimEnabled = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_SCIM_ENABLED);
        if (scimEnabled != null) {
            return Boolean.parseBoolean(scimEnabled);
        } else {
            return false;
        }
    }

    /**
     * {@inheritDoc}                  doAddInternalRole
     */
    public final String[] getHybridRoles() throws UserStoreException {
        return hybridRoleManager.getHybridRoles("*");
    }

    /**
     * {@inheritDoc}
     */
    public final String[] getRoleNames() throws UserStoreException {
        return getRoleNames(false);
    }

    /**
     * {@inheritDoc}
     */
    public final String[] getRoleNames(boolean noHybridRoles) throws UserStoreException {
        return getRoleNames("*", -1, noHybridRoles, true, true);
    }


    /**
     * @param roleName
     * @param userList
     * @param permissions
     * @throws UserStoreException
     */
    protected void doAddInternalRole(String roleName, String[] userList,
                                     org.wso2.carbon.user.api.Permission[] permissions)
            throws UserStoreException {

        // #################### Domain Name Free Zone Starts Here ################################

        if (roleName.contains(UserCoreConstants.DOMAIN_SEPARATOR)
                && roleName.toLowerCase().startsWith(APPLICATION_DOMAIN.toLowerCase())) {
            if (hybridRoleManager.isExistingRole(roleName)) {
                throw new UserStoreException("Role name: " + roleName
                        + " in the system. Please pick another role name.");
            }

            hybridRoleManager.addHybridRole(roleName, userList);

        } else {
            if (hybridRoleManager.isExistingRole(UserCoreUtil.removeDomainFromName(roleName))) {
                throw new UserStoreException("Role name: " + roleName
                        + " in the system. Please pick another role name.");
            }

            hybridRoleManager.addHybridRole(UserCoreUtil.removeDomainFromName(roleName), userList);
        }



        if (permissions != null) {
            for (org.wso2.carbon.user.api.Permission permission : permissions) {
                String resourceId = permission.getResourceId();
                String action = permission.getAction();
                // This is a special case. We need to pass domain aware name.
                userRealm.getAuthorizationManager().authorizeRole(
                        UserCoreUtil.addInternalDomainName(roleName), resourceId, action);
            }
        }

        if ((userList != null) && (userList.length > 0)) {
            clearUserRolesCacheByTenant(this.tenantId);
        }
    }


    /**
     * TODO This method would returns the role Name actually this must be implemented in interface.
     * As it is not good to change the API in point release. This has been added to Abstract class
     *
     * @param filter
     * @param maxItemLimit
     * @param noInternalRoles
     * @return
     * @throws UserStoreException
     */
    public final String[] getRoleNames(String filter, int maxItemLimit, boolean noInternalRoles,
                                       boolean noSystemRole, boolean noSharedRoles)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, int.class, boolean.class, boolean.class, boolean.class};
            Object object = callSecure("getRoleNames", new Object[]{filter, maxItemLimit, noInternalRoles,
                    noSystemRole, noSharedRoles}, argTypes);
            return (String[]) object;
        }

        String[] roleList = new String[0];

        if (!noInternalRoles && (filter.toLowerCase().startsWith(APPLICATION_DOMAIN.toLowerCase()))) {
            roleList = hybridRoleManager.getHybridRoles(filter);
        } else if (!noInternalRoles) {
            roleList = hybridRoleManager.getHybridRoles(UserCoreUtil.removeDomainFromName(filter));
        }

        if (!noSystemRole) {
            String[] systemRoles = systemUserRoleManager.getSystemRoles();
            roleList = UserCoreUtil.combineArrays(roleList, systemRoles);
        }

        int index;
        index = filter.indexOf(CarbonConstants.DOMAIN_SEPARATOR);

        // Check whether we have a secondary UserStoreManager setup.
        if (index > 0) {
            // Using the short-circuit. User name comes with the domain name.
            String domain = filter.substring(0, index);

            UserStoreManager secManager = getSecondaryUserStoreManager(domain);
            if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)
                    || APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
                return new String[0];
            }
            if (secManager != null) {
                // We have a secondary UserStoreManager registered for this domain.
                filter = filter.substring(index + 1);
                if (secManager instanceof MongoDBUserStoreManager) {
                    if (readGroupsEnabled) {
                        String[] externalRoles = ((MongoDBUserStoreManager) secManager)
                                .doGetRoleNames(filter, maxItemLimit);
                        return UserCoreUtil.combineArrays(roleList, externalRoles);
                    }
                } else {
                    String[] externalRoles = secManager.getRoleNames();
                    return UserCoreUtil.combineArrays(roleList, externalRoles);
                }
            } else {
                throw new UserStoreException("Invalid Domain Name");
            }
        } else if (index == 0) {
            if (readGroupsEnabled) {
                String[] externalRoles = doGetRoleNames(filter.substring(index + 1), maxItemLimit);
                return UserCoreUtil.combineArrays(roleList, externalRoles);
            }
        }

        if (readGroupsEnabled) {
            String[] externalRoles = doGetRoleNames(filter, maxItemLimit);
            roleList = UserCoreUtil.combineArrays(externalRoles, roleList);
        }

        String primaryDomain = getMyDomainName();

        if (this.getSecondaryUserStoreManager() != null) {
            for (Map.Entry<String, UserStoreManager> entry : userStoreManagerHolder.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(primaryDomain)) {
                    continue;
                }
                UserStoreManager storeManager = entry.getValue();
                if (storeManager instanceof MongoDBUserStoreManager) {
                    try {
                        if (readGroupsEnabled) {
                            String[] secondRoleList = ((MongoDBUserStoreManager) storeManager)
                                    .doGetRoleNames(filter, maxItemLimit);
                            roleList = UserCoreUtil.combineArrays(roleList, secondRoleList);
                        }
                    } catch (UserStoreException e) {
                        // We can ignore and proceed. Ignore the results from this user store.
                        log.error(e);
                    }
                } else {
                    roleList = UserCoreUtil.combineArrays(roleList, storeManager.getRoleNames());
                }
            }
        }
        return roleList;
    }

    /**
     * @param userName
     * @param claims
     * @param domainName
     * @return
     * @throws UserStoreException
     */
    private Map<String, String> doGetUserClaimValues(String userName, String[] claims,
                                                     String domainName, String profileName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String[].class, String.class, String.class};
            Object object = callSecure("doGetUserClaimValues", new Object[]{userName, claims, domainName,
                    profileName}, argTypes);
            return (Map<String, String>) object;
        }

        // Here the user name should be domain-less.
        boolean requireRoles = false;
        boolean requireIntRoles = false;
        boolean requireExtRoles = false;
        String roleClaim = null;

        if (profileName == null || profileName.trim().length() == 0) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }

        Set<String> propertySet = new HashSet<String>();
        for (String claim : claims) {

            // There can be cases some claim values being requested for claims
            // we don't have.
            String property = null;
            try {
                property = getClaimAtrribute(claim, userName, domainName);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException(e);
            }
            if (property != null
                    && (!UserCoreConstants.ROLE_CLAIM.equalsIgnoreCase(claim)
                    || !UserCoreConstants.INT_ROLE_CLAIM.equalsIgnoreCase(claim) ||
                    !UserCoreConstants.EXT_ROLE_CLAIM.equalsIgnoreCase(claim))) {
                propertySet.add(property);
            }

            if (UserCoreConstants.ROLE_CLAIM.equalsIgnoreCase(claim)) {
                requireRoles = true;
                roleClaim = claim;
            } else if (UserCoreConstants.INT_ROLE_CLAIM.equalsIgnoreCase(claim)) {
                requireIntRoles = true;
                roleClaim = claim;
            } else if (UserCoreConstants.EXT_ROLE_CLAIM.equalsIgnoreCase(claim)) {
                requireExtRoles = true;
                roleClaim = claim;
            }
        }

        String[] properties = propertySet.toArray(new String[propertySet.size()]);
        Map<String, String> uerProperties = this.getUserPropertyValues(userName, properties,
                profileName);

        List<String> getAgain = new ArrayList<String>();
        Map<String, String> finalValues = new HashMap<String, String>();

        for (String claim : claims) {
            ClaimMapping mapping;
            try {
                mapping = (ClaimMapping) claimManager.getClaimMapping(claim);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException(e);
            }
            String property = null;
            String value = null;
            if (mapping != null) {
                if (domainName != null) {
                    Map<String, String> attrMap = mapping.getMappedAttributes();
                    if (attrMap != null) {
                        String attr = null;
                        if ((attr = attrMap.get(domainName.toUpperCase())) != null) {
                            property = attr;
                        } else {
                            property = mapping.getMappedAttribute();
                        }
                    }
                } else {
                    property = mapping.getMappedAttribute();
                }

                value = uerProperties.get(property);

                if (profileName.equals(UserCoreConstants.DEFAULT_PROFILE)) {
                    // Check whether we have a value for the requested attribute
                    if (value != null && value.trim().length() > 0) {
                        finalValues.put(claim, value);
                    }
                } else {
                    if (value != null && value.trim().length() > 0) {
                        finalValues.put(claim, value);
                    }
                }
            } else {
                if (property == null && claim.equals(DISAPLAY_NAME_CLAIM)) {
                    property = this.realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
                }

                value = uerProperties.get(property);
                if (value != null && value.trim().length() > 0) {
                    finalValues.put(claim, value);
                }
            }
        }

        if (getAgain.size() > 0) {
            // oh the beautiful recursion
            Map<String, String> mapClaimValues = this.getUserClaimValues(userName,
                    (String[]) getAgain.toArray(new String[getAgain.size()]),
                    profileName);

            Iterator<Map.Entry<String, String>> ite3 = mapClaimValues.entrySet().iterator();
            while (ite3.hasNext()) {
                Map.Entry<String, String> entry = ite3.next();
                if (entry.getValue() != null) {
                    finalValues.put(entry.getKey(), entry.getValue());
                }
            }
        }

        // We treat roles claim in special way.
        String[] roles = null;

        if (requireRoles) {
            roles = getRoleListOfUser(userName);
        } else if (requireIntRoles) {
            roles = doGetInternalRoleListOfUser(userName, "*");
        } else if (requireExtRoles) {

            List<String> rolesList = new ArrayList<String>();
            String[] externalRoles = doGetExternalRoleListOfUser(userName, "*");
            rolesList.addAll(Arrays.asList(externalRoles));
            //if only shared enable
            if (isSharedGroupEnabled()) {
                String[] sharedRoles = doGetSharedRoleListOfUser(userName, null, "*");
                if (sharedRoles != null) {
                    rolesList.addAll(Arrays.asList(sharedRoles));
                }
            }

            roles = rolesList.toArray(new String[rolesList.size()]);
        }

        if (roles != null && roles.length > 0) {
            String delim = "";
            StringBuffer roleBf = new StringBuffer();
            for (String role : roles) {
                roleBf.append(delim).append(role);
                delim = ",";
            }
            finalValues.put(roleClaim, roleBf.toString());
        }

        return finalValues;
    }

    /**
     * @return
     */
    protected String getEveryOneRoleName() {
        return realmConfig.getEveryOneRoleName();
    }

    /**
     * @return
     */
    protected String getAdminRoleName() {
        return realmConfig.getAdminRoleName();
    }

    /**
     * @param credential
     * @return
     * @throws UserStoreException
     */
    protected boolean checkUserPasswordValid(Object credential) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{Object.class};
            Object object = callSecure("checkUserPasswordValid", new Object[]{credential}, argTypes);
            return (Boolean) object;
        }

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

        String regularExpression = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX);
        return regularExpression == null || isFormatCorrect(regularExpression, password);
    }

    /**
     * @param userName
     * @return
     * @throws UserStoreException
     */
    protected boolean checkUserNameValid(String userName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            Object object = callSecure("checkUserNameValid", new Object[]{userName}, argTypes);
            return (Boolean) object;
        }

        if (userName == null || CarbonConstants.REGISTRY_SYSTEM_USERNAME.equals(userName)) {
            return false;
        }

        userName = userName.trim();

        if (userName.length() < 1) {
            return false;
        }

        String regularExpression = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX);

        if (regularExpression != null) {
            regularExpression = regularExpression.trim();
        }

        return regularExpression == null || regularExpression.equals("")
                || isFormatCorrect(regularExpression, userName);

    }

    /**
     * @param roleName
     * @return
     */
    protected boolean isRoleNameValid(String roleName) {
        if (roleName == null) {
            return false;
        }

        if (roleName.length() < 1) {
            return false;
        }

        String regularExpression = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
        if (regularExpression != null) {
            if (!isFormatCorrect(regularExpression, roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param tenantID
     * @param userName
     * @return
     */
    protected String[] getRoleListOfUserFromCache(int tenantID, String userName) {
        if (userRolesCache != null) {
            String usernameWithDomain = UserCoreUtil.addDomainToName(userName, getMyDomainName());
            return userRolesCache.getRolesListOfUser(cacheIdentifier, tenantID, usernameWithDomain);
        }
        return null;
    }

    /**
     * @param tenantID
     */
    protected void clearUserRolesCacheByTenant(int tenantID) {
        if (userRolesCache != null) {
            userRolesCache.clearCacheByTenant(tenantID);
        }
        AuthorizationCache authorizationCache = AuthorizationCache.getInstance();
        authorizationCache.clearCacheByTenant(tenantID);
    }

    /**
     * @param userName
     */
    protected void clearUserRolesCache(String userName) {
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, getMyDomainName());
        if (userRolesCache != null) {
            userRolesCache.clearCacheEntry(cacheIdentifier, tenantId, usernameWithDomain);
        }
        AuthorizationCache authorizationCache = AuthorizationCache.getInstance();
        authorizationCache.clearCacheByUser(tenantId, usernameWithDomain);
    }

    /**
     * @param tenantID
     * @param userName
     * @param roleList
     */
    protected void addToUserRolesCache(int tenantID, String userName, String[] roleList) {
        if (userRolesCache != null) {
            String usernameWithDomain = UserCoreUtil.addDomainToName(userName, getMyDomainName());
            userRolesCache.addToCache(cacheIdentifier, tenantID, usernameWithDomain, roleList);
            AuthorizationCache authorizationCache = AuthorizationCache.getInstance();
            authorizationCache.clearCacheByTenant(tenantID);
        }
    }

    /**
     * {@inheritDoc}
     */
    protected void initUserRolesCache() {

        String userRolesCacheEnabledString = (realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLES_CACHE_ENABLED));

        String userCoreCacheIdentifier = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_CORE_CACHE_IDENTIFIER);

        if (userCoreCacheIdentifier != null && userCoreCacheIdentifier.trim().length() > 0) {
            cacheIdentifier = userCoreCacheIdentifier;
        } else {
            cacheIdentifier = UserCoreConstants.DEFAULT_CACHE_IDENTIFIER;
        }

        if (userRolesCacheEnabledString != null && !userRolesCacheEnabledString.equals("")) {
            userRolesCacheEnabled = Boolean.parseBoolean(userRolesCacheEnabledString);
            if (log.isDebugEnabled()) {
                log.debug("User Roles Cache is configured to:" + userRolesCacheEnabledString);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.info("User Roles Cache is not configured. Default value: "
                        + userRolesCacheEnabled + " is taken.");
            }
        }

        if (userRolesCacheEnabled) {
            int timeOut = UserCoreConstants.USER_ROLE_CACHE_DEFAULT_TIME_OUT;
            String timeOutString = realmConfig.
                    getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_ROLE_CACHE_TIME_OUT);
            if (timeOutString != null) {
                timeOut = Integer.parseInt(timeOutString);
            }
            userRolesCache = UserRolesCache.getInstance();
            userRolesCache.setTimeOut(timeOut);
        }

    }

    /**
     * @param regularExpression
     * @param attribute
     * @return
     */
    private boolean isFormatCorrect(String regularExpression, String attribute) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(attribute);
        return m2.matches();
    }

    /**
     * This is to replace escape characters in user name at user login if replace escape characters
     * enabled in user-mgt.xml. Some User Stores like ApacheDS stores user names by replacing escape
     * characters. In that case, we have to parse the username accordingly.
     *
     * @param userName
     */
    protected String replaceEscapeCharacters(String userName) {

        if (log.isDebugEnabled()) {
            log.debug("Replacing escape characters in " + userName);
        }
        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharactersAtUserLogin = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters at userlogin is configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
            if (replaceEscapeCharactersAtUserLogin) {
                // Currently only '\' & '\\' are identified as escape characters
                // that needs to be
                // replaced.
                return userName.replaceAll("\\\\", "\\\\\\\\");
            }
        }
        return userName;
    }

    /**
     * TODO: Remove this method. We should not use DTOs
     *
     * @return
     * @throws UserStoreException
     */
    public RoleDTO[] getAllSecondaryRoleDTOs() throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{};
            Object object = callSecure("getAllSecondaryRoleDTOs", new Object[]{}, argTypes);
            return (RoleDTO[]) object;
        }

        UserStoreManager secondary = this.getSecondaryUserStoreManager();
        List<RoleDTO> roleList = new ArrayList<RoleDTO>();
        while (secondary != null) {
            String domain = secondary.getRealmConfiguration().getUserStoreProperty(
                    UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            String[] roles = secondary.getRoleNames(true);
            if (roles != null && roles.length > 0) {
                Collections.addAll(roleList,UserCoreUtil.convertRoleNamesToRoleDTO(roles, domain));
            }
            secondary = secondary.getSecondaryUserStoreManager();
        }
        return roleList.toArray(new RoleDTO[roleList.size()]);
    }

    /**
     * @param roleName
     * @param userList
     * @param permissions
     * @throws UserStoreException
     */
    public void addSystemRole(String roleName, String[] userList, TreeNode.Permission[] permissions)
            throws UserStoreException {

        if (!isRoleNameValid(roleName)) {
            String regEx = realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
            throw new UserStoreException(
                    INVALID_ROLE + "Role name not valid. Role name must be a non null string with following format, "
                            + regEx);
        }

        if (systemUserRoleManager.isExistingRole(roleName)) {
            throw new UserStoreException("Role name: " + roleName
                    + " in the system. Please pick another role name.");
        }
        systemUserRoleManager.addSystemRole(roleName, userList);
    }

    /**
     * @param userName
     * @param filter
     * @return
     * @throws UserStoreException
     */
    public final String[] doGetRoleListOfUser(String userName, String filter)
            throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class};
            Object object = callSecure("doGetRoleListOfUser", new Object[]{userName, filter}, argTypes);
            return (String[]) object;
        }

        String[] roleList;

        String[] internalRoles = doGetInternalRoleListOfUser(userName, filter);

        String[] modifiedExternalRoleList = new String[0];

        if (readGroupsEnabled && doCheckExistingUser(userName)) {
            List<String> roles = new ArrayList<String>();
            String[] externalRoles = doGetExternalRoleListOfUser(userName, "*");
            roles.addAll(Arrays.asList(externalRoles));
            if (isSharedGroupEnabled()) {
                String[] sharedRoles = doGetSharedRoleListOfUser(userName, null, "*");
                if (sharedRoles != null) {
                    roles.addAll(Arrays.asList(sharedRoles));
                }
            }
            modifiedExternalRoleList =
                    UserCoreUtil.addDomainToNames(roles.toArray(new String[roles.size()]),
                            getMyDomainName());
        }

        roleList = UserCoreUtil.combine(internalRoles, Arrays.asList(modifiedExternalRoleList));

        addToUserRolesCache(this.tenantId, userName, roleList);

        return roleList;
    }


    /**
     * @param claimList
     * @return
     * @throws UserStoreException
     */
    protected List<String> getMappingAttributeList(List<String> claimList)
            throws UserStoreException {
        ArrayList<String> attributeList = null;
        Iterator<String> claimIter = null;

        attributeList = new ArrayList<String>();
        if (claimList == null) {
            return attributeList;
        }
        claimIter = claimList.iterator();
        while (claimIter.hasNext()) {
            try {
                attributeList.add(claimManager.getAttributeName(claimIter.next()));
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException(e);
            }
        }
        return attributeList;
    }

    /**
     * @return whether this is the initial startup
     * @throws UserStoreException
     */
    protected void doInitialUserAdding() throws UserStoreException {

        String systemUser = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME);
        String systemRole = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME);

        if (!systemUserRoleManager.isExistingSystemUser(systemUser)) {
            systemUserRoleManager.addSystemUser(systemUser,
                    UserCoreUtil.getPolicyFriendlyRandomPassword(systemUser), null);
        }

        if (!systemUserRoleManager.isExistingRole(systemRole)) {
            systemUserRoleManager.addSystemRole(systemRole, new String[]{systemUser});
        }

        if (!hybridRoleManager.isExistingRole(UserCoreUtil.removeDomainFromName(realmConfig
                .getEveryOneRoleName()))) {
            hybridRoleManager.addHybridRole(
                    UserCoreUtil.removeDomainFromName(realmConfig.getEveryOneRoleName()), null);
        }
    }

    protected boolean isInitSetupDone() throws UserStoreException {

        boolean isInitialSetUp = false;
        String systemUser = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME);
        String systemRole = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME);

        if (systemUserRoleManager.isExistingSystemUser(systemUser)) {
            isInitialSetUp = true;
        }

        if (systemUserRoleManager.isExistingRole(systemRole)) {
            isInitialSetUp = true;
        }

        return isInitialSetUp;
    }

    /**
     * @param type
     * @return
     * @throws UserStoreException
     */
    public Map<String, Integer> getMaxListCount(String type) throws UserStoreException {

        if (!type.equals(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST)
                && !type.equals(UserCoreConstants.RealmConfig.PROPERTY_MAX_ROLE_LIST)) {
            throw new UserStoreException("Invalid count parameter");
        }

        if (type.equals(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST)
                && maxUserListCount != null) {
            return maxUserListCount;
        }

        if (type.equals(UserCoreConstants.RealmConfig.PROPERTY_MAX_ROLE_LIST)
                && maxRoleListCount != null) {
            return maxRoleListCount;
        }

        Map<String, Integer> maxListCount = new HashMap<String, Integer>();
        for (Map.Entry<String, UserStoreManager> entry : userStoreManagerHolder.entrySet()) {
            UserStoreManager storeManager = entry.getValue();
            String maxConfig = storeManager.getRealmConfiguration().getUserStoreProperty(type);

            if (maxConfig == null) {
                // set a default value
                maxConfig = MAX_LIST_LENGTH;
            }
            maxListCount.put(entry.getKey(), Integer.parseInt(maxConfig));
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME) == null) {
            String maxConfig = realmConfig.getUserStoreProperty(type);
            if (maxConfig == null) {
                // set a default value
                maxConfig = MAX_LIST_LENGTH;
            }
            maxListCount.put(null, Integer.parseInt(maxConfig));
        }

        if (type.equals(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST)) {
            this.maxUserListCount = maxListCount;
            return this.maxUserListCount;
        } else if (type.equals(UserCoreConstants.RealmConfig.PROPERTY_MAX_ROLE_LIST)) {
            this.maxRoleListCount = maxListCount;
            return this.maxRoleListCount;
        } else {
            throw new UserStoreException("Invalid count parameter");
        }
    }

    /**
     * @return
     */
    protected String getMyDomainName() {
        return UserCoreUtil.getDomainName(realmConfig);
    }

    public void deletePersistedDomain(String domain) throws UserStoreException {
        if (domain != null) {
            if (log.isDebugEnabled()) {
                log.debug("Deleting persisted domain " + domain);
            }
            UserCoreUtil.deletePersistedDomain(domain, this.tenantId,dataSource);
        }
    }

    public void updatePersistedDomain(String oldDomain, String newDomain) throws UserStoreException {
        if (oldDomain != null && newDomain != null) {
            // Checks for the newDomain exists already
            // Traverse through realm configuration chain since USM chain doesn't contains the disabled USMs
            RealmConfiguration realmConfigTmp = this.getRealmConfiguration();
            while (realmConfigTmp != null) {
                String domainName = realmConfigTmp.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                if (newDomain.equalsIgnoreCase(domainName)) {
                    throw new UserStoreException("Cannot update persisted domain name " + oldDomain + " into " + newDomain + ". New domain name already in use");
                }
                realmConfigTmp = realmConfigTmp.getSecondaryRealmConfig();
            }

            if (log.isDebugEnabled()) {
                log.debug("Renaming persisted domain " + oldDomain + " to " + newDomain);
            }
            UserCoreUtil.updatePersistedDomain(oldDomain, newDomain, this.tenantId, dataSource);

        }
    }

    /**
     * Checks whether the role is a shared role or not
     *
     * @param roleName
     * @param roleNameBase
     * @return
     */
    public boolean isSharedRole(String roleName, String roleNameBase) {

        // Only checks the shared groups are enabled
        return isSharedGroupEnabled();
    }

    /**
     * Checks whether the provided role name belongs to the logged in tenant.
     * This check is done using the domain name which is appended at the end of
     * the role name
     *
     * @param roleName
     * @return
     */
    protected boolean isOwnRole(String roleName) {
        return true;
    }

    public void addRole(String roleName, String[] userList,
                        org.wso2.carbon.user.api.Permission[] permissions)
            throws org.wso2.carbon.user.api.UserStoreException {
        addRole(roleName, userList, permissions, false);

    }

    public boolean isOthersSharedRole(String roleName) {
        return false;
    }

    public void notifyListeners(String domainName) {
        for (UserStoreManagerConfigurationListener aListener : listener) {
            aListener.propertyChange(domainName);
        }
    }

    public void addChangeListener(UserStoreManagerConfigurationListener newListener) {
        listener.add(newListener);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private UserStoreManager createSecondaryUserStoreManager(RealmConfiguration realmConfig,
                                                             UserRealm realm) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{RealmConfiguration.class, UserRealm.class};
            Object object = callSecure("createSecondaryUserStoreManager", new Object[]{realmConfig, realm}, argTypes);
            return (UserStoreManager) object;
        }

        // setting global realm configurations such as everyone role, admin role and admin user
        realmConfig.setEveryOneRoleName(this.realmConfig.getEveryOneRoleName());
        realmConfig.setAdminUserName(this.realmConfig.getAdminUserName());
        realmConfig.setAdminRoleName(this.realmConfig.getAdminRoleName());

        String className = realmConfig.getUserStoreClass();
        if (className == null) {
            String errmsg = "Unable to add user store. UserStoreManager class name is null.";
            log.error(errmsg);
            throw new UserStoreException(errmsg);
        }

        HashMap<String, Object> properties = new HashMap<String, Object>();
        properties.put(UserCoreConstants.DATA_SOURCE, this.db);
        properties.put(UserCoreConstants.FIRST_STARTUP_CHECK, false);

        Class[] initClassOpt1 = new Class[]{RealmConfiguration.class, Map.class,
                ClaimManager.class, ProfileConfigurationManager.class, UserRealm.class,
                Integer.class};
        Object[] initObjOpt1 = new Object[]{realmConfig, properties, realm.getClaimManager(), null, realm,
                tenantId};

        // These two methods won't be used
        Class[] initClassOpt2 = new Class[]{RealmConfiguration.class, Map.class,
                ClaimManager.class, ProfileConfigurationManager.class, UserRealm.class};
        Object[] initObjOpt2 = new Object[]{realmConfig, properties, realm.getClaimManager(), null, realm};

        Class[] initClassOpt3 = new Class[]{RealmConfiguration.class, Map.class};
        Object[] initObjOpt3 = new Object[]{realmConfig, properties};

        try {
            Class clazz = Class.forName(className);
            Constructor constructor = null;
            Object newObject = null;

            if (log.isDebugEnabled()) {
                log.debug("Start initializing class with the first option");
            }

            try {
                constructor = clazz.getConstructor(initClassOpt1);
                newObject = constructor.newInstance(initObjOpt1);
                return (UserStoreManager) newObject;
            } catch (NoSuchMethodException e) {
                // if not found try again.
                if (log.isDebugEnabled()) {
                    log.debug("Cannont initialize " + className + " using the option 1");
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("End initializing class with the first option");
            }

            try {
                constructor = clazz.getConstructor(initClassOpt2);
                newObject = constructor.newInstance(initObjOpt2);
                return (UserStoreManager) newObject;
            } catch (NoSuchMethodException e) {
                // if not found try again.
                if (log.isDebugEnabled()) {
                    log.debug("Cannot initialize " + className + " using the option 2");
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("End initializing class with the second option");
            }

            try {
                constructor = clazz.getConstructor(initClassOpt3);
                newObject = constructor.newInstance(initObjOpt3);
                return (UserStoreManager) newObject;
            } catch (NoSuchMethodException e) {
                // cannot initialize in any of the methods. Throw exception.
                String message = "Cannot initialize " + className + ". Error " + e.getMessage();
                log.error(message);
                throw new UserStoreException(message);
            }

        } catch (Throwable e) {
            log.error("Cannot create " + className, e);
            throw new UserStoreException(e.getMessage() + "Type " + e.getClass(), e);
        }

    }

    /**
     * Adding new User Store Manager to USM chain
     *
     * @param userStoreRealmConfig
     * @param realm
     * @throws UserStoreException
     */
    public void addSecondaryUserStoreManager(RealmConfiguration userStoreRealmConfig,
                                             UserRealm realm) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{RealmConfiguration.class, UserRealm.class};
            callSecure("addSecondaryUserStoreManager", new Object[]{userStoreRealmConfig, realm}, argTypes);
            return;
        }

        // Creating new UserStoreManager
        UserStoreManager manager = createSecondaryUserStoreManager(userStoreRealmConfig, realm);

        String domainName = userStoreRealmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        if (domainName != null) {
            if (this.getSecondaryUserStoreManager(domainName) != null) {
                String errmsg = "Could not initialize new user store manager : " + domainName
                        + " Duplicate domain names not allowed.";
                if (log.isDebugEnabled()) {
                    log.debug(errmsg);
                }
                throw new UserStoreException(errmsg);
            } else {
                boolean isDisabled = Boolean.parseBoolean(userStoreRealmConfig
                        .getUserStoreProperty(UserCoreConstants.RealmConfig.USER_STORE_DISABLED));
                if (isDisabled) {
                    log.warn("Secondary user store disabled with domain " + domainName + ".");
                } else {
                    // Fulfilled requirements for adding UserStore,

                    // Now adding UserStoreManager to end of the UserStoreManager chain
                    UserStoreManager tmpUserStoreManager = this;
                    while (tmpUserStoreManager.getSecondaryUserStoreManager() != null) {
                        tmpUserStoreManager = tmpUserStoreManager.getSecondaryUserStoreManager();
                    }
                    tmpUserStoreManager.setSecondaryUserStoreManager(manager);

                    // update domainName-USM map to retrieve USM directly by its domain name
                    this.addSecondaryUserStoreManager(domainName.toUpperCase(), tmpUserStoreManager.getSecondaryUserStoreManager());

                    if (log.isDebugEnabled()) {
                        log.debug("UserStoreManager : " + domainName + "added to the list");
                    }
                }
            }
        } else {
            log.warn("Could not initialize new user store manager.  "
                    + "Domain name is not defined");
        }
    }

    /**
     * Remove given User Store Manager from USM chain
     *
     * @param userStoreDomainName
     * @throws UserStoreException
     */
    public void removeSecondaryUserStoreManager(String userStoreDomainName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class};
            callSecure("removeSecondaryUserStoreManager", new Object[]{userStoreDomainName}, argTypes);
            return;
        }

        if (userStoreDomainName == null) {
            throw new UserStoreException("Cannot remove user store. User store domain name is null");
        }
        if ("".equals(userStoreDomainName)) {
            throw new UserStoreException("Cannot remove user store. User store domain name is empty");
        }
//    	if(!this.userStoreManagerHolder.containsKey(userStoreDomainName.toUpperCase())) {
//    		throw new UserStoreException("Cannot remove user store. User store domain name does not exists");
//    	}

        userStoreDomainName = userStoreDomainName.toUpperCase();

        boolean isUSMContainsInMap = false;
        if (this.userStoreManagerHolder.containsKey(userStoreDomainName.toUpperCase())) {
            isUSMContainsInMap = true;
            this.userStoreManagerHolder.remove(userStoreDomainName.toUpperCase());
            if (log.isDebugEnabled()) {
                log.debug("UserStore: " + userStoreDomainName + " removed from map");
            }
        }

        boolean isUSMConatainsInChain = false;
        UserStoreManager prevUserStoreManager = this;
        while (prevUserStoreManager.getSecondaryUserStoreManager() != null) {
            UserStoreManager secondaryUSM = prevUserStoreManager.getSecondaryUserStoreManager();
            if (secondaryUSM.getRealmConfiguration().getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME).equalsIgnoreCase(userStoreDomainName)) {
                isUSMConatainsInChain = true;
                // Omit deleting user store manager from the chain
                prevUserStoreManager.setSecondaryUserStoreManager(secondaryUSM.getSecondaryUserStoreManager());
                log.info("User store: " + userStoreDomainName + " of tenant:" + tenantId + " is removed from user store chain.");
                return;
            }
            prevUserStoreManager = secondaryUSM;
        }

        if (!isUSMContainsInMap && isUSMConatainsInChain) {
            throw new UserStoreException("Removed user store manager : " + userStoreDomainName + " didnt exists in userStoreManagerHolder map");
        } else if (isUSMContainsInMap && !isUSMConatainsInChain) {
            throw new UserStoreException("Removed user store manager : " + userStoreDomainName + " didnt exists in user store manager chain");
        }
    }

    public HybridRoleManager getInternalRoleManager() {
        return hybridRoleManager;
    }

    public Claim[] getUserClaimValues(String userName, String profileName) throws UserStoreException {

        if (!isSecureCall.get()) {
            Class argTypes[] = new Class[]{String.class, String.class};
            Object object = callSecure("getUserClaimValues", new Object[]{userName, profileName}, argTypes);
            return (Claim[]) object;
        }

        UserStore userStore = getUserStore(userName);
        if (userStore.isRecurssive()) {
            return userStore.getUserStoreManager().getUserClaimValues(
                    userStore.getDomainFreeName(), profileName);
        }

        // #################### Domain Name Free Zone Starts Here ################################
        // If user does not exist, throw exception
        if (!doCheckExistingUser(userName)) {
            throw new UserStoreException(USER_NOT_FOUND + ": User " + userName + "does not exist in: "
                    + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
        }

        if (profileName == null || profileName.trim().length() == 0) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }

        String[] claims;
        try {
            claims = claimManager.getAllClaimUris();
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException(e);
        }

        Map<String, String> values = this.getUserClaimValues(userName, claims, profileName);
        Claim[] finalValues = new Claim[values.size()];
        int i = 0;
        for (Iterator<Map.Entry<String, String>> ite = values.entrySet().iterator(); ite.hasNext(); ) {
            Map.Entry<String, String> entry = ite.next();
            Claim claim = new Claim();
            claim.setValue(entry.getValue());
            claim.setClaimUri(entry.getKey());
            String displayTag;
            try {
                displayTag = claimManager.getClaim(entry.getKey()).getDisplayTag();
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException(e);
            }
            claim.setDisplayTag(displayTag);
            finalValues[i] = claim;
            i++;
        }

        return finalValues;
    }

}
