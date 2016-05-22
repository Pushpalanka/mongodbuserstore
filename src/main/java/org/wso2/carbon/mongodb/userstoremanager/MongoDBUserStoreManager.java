package org.wso2.carbon.mongodb.userstoremanager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import com.mongodb.*;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.mongodb.query.*;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.api.ProfileConfigurationManager;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.jdbc.JDBCRoleContext;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.mongodb.util.MongoDBRealmUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.mongodb.query.MongoQueryException;

public class MongoDBUserStoreManager extends AbstractUserStoreManager {

	private int tenantId;
	private DB db;
	private DBCollection collection;
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    protected Random random = new Random();
    private static final String SHA_1_PRNG = "SHA1PRNG";
	private org.apache.commons.logging.Log log = LogFactory.getLog(MongoDBUserStoreManager.class);

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

        db = (DB) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("User Management Data Source is null");
        }

        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);


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
            DBCursor cursor = prepStmt.find();
            while(cursor.hasNext()){

                String name = cursor.next().get("UM_ATTR_NAME").toString();
                String value = cursor.next().get("UM_PROFILE_VALUE").toString();
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
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_IS_ROLE_EXISTING);
        if (mongoQuery == null) {
            throw new UserStoreException("The MongoDB Query statement for is role existing role null");
        }
        if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){

            isExisting = isValueExisting(mongoQuery,null,roleName,((JDBCRoleContext) context).getTenantId());
        }else{
            isExisting = isValueExisting(mongoQuery, null, roleName);
        }
        return isExisting;
    }

    protected boolean isValueExisting(String mongoQuery, DB db, Object... params) throws UserStoreException{

        MongoPreparedStatement prepStmt = null;
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
            log.error("Using sql : " + mongoQuery);
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            if(doClose){
                prepStmt.close();
            }
        }
    }

	protected boolean doCheckExistingUser(String userName) throws UserStoreException {

        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_IS_USER_EXISTING);
        if (mongoQuery == null) {
            throw new UserStoreException("The sql statement for is user existing null");
        }
        boolean isExisting = false;
        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if ("true".equals(isUnique)
                && !CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
            String uniquenesSql = realmConfig
                    .getUserStoreProperty(MongoDBRealmConstants.USER_NAME_UNIQUE);
            isExisting = isValueExisting(uniquenesSql, null, userName);
            if (log.isDebugEnabled()) {
                log.debug("The username should be unique across tenants.");
            }
        } else {
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                isExisting = isValueExisting(mongoQuery, null, userName, tenantId);
            } else {
                isExisting = isValueExisting(mongoQuery, null, userName);
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
            throw new UserStoreException("Authentication Failure");
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
        String saltValue = null;
        if (mongoQuery == null) {
            throw new UserStoreException("The sql statement for delete user claim value is null");
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

        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            updateStringValuesToDatabase(null, mongoQuery, password, "", false, new Date(), userName,
                    tenantId);
        } else if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue != null) {
            updateStringValuesToDatabase(null, mongoQuery, password, saltValue, false, new Date(),
                    userName, tenantId);
        } else if (!mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            updateStringValuesToDatabase(null, mongoQuery, password, "", false, new Date(), userName);
        } else {
            updateStringValuesToDatabase(null, mongoQuery, password, saltValue, false, new Date(),
                    userName);
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
                                              Object... params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try{

            if(dbConnection == null) {

                localConnection = true;
                dbConnection = loadUserStoreSpacificDataSoruce();
            }
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Invalid data provided");
                    } else if (param instanceof String) {
                        if(i==0) {

                            prepStmt.setString("UM_USER_NAME", (String) param);
                        }else{

                            prepStmt.setString("UM_USER_PASSWORD", (String) param);
                        }
                    } else if (param instanceof Integer) {
                        prepStmt.setInt("UM_TENANT_ID", (Integer) param);
                    } else if (param instanceof Date) {
                        // Timestamp timestamp = new Timestamp(((Date) param).getTime());
                        // prepStmt.setTimestamp(i + 1, timestamp);
                        prepStmt.setTimeStamp("UM_CHANGED_TIME", new BSONTimestamp((int) System.currentTimeMillis(), 1));
                    } else if (param instanceof Boolean) {
                        prepStmt.setBoolean("UM_REQUIRE_CHANGE", (Boolean) param);
                    }
                }
            }
            WriteResult result = prepStmt.update();
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
            DBCursor cursor = null;
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            prepStmt.setString("users.UM_USER_NAME", userName);
            prepStmt.setString("UM_PROFILE_ID", profileName);
            prepStmt.setString("UM_ATTR_NAME", property);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                prepStmt.setInt("UM_TENANT_ID", tenantId);
                prepStmt.setInt("users.UM_TENANT_ID", tenantId);
            }
            cursor = prepStmt.find();
            while(cursor.hasNext()){

                value = cursor.next().get("UM_ATTR_VALUE").toString();
            }
            return value;
        }catch (MongoQueryException ex){

            String msg = "Error occurred while retrieving user profile property for user : " + userName +
                    " & property name : " + property + " & profile name : " + profileName;
            if (log.isDebugEnabled()) {
                log.debug(msg, ex);
            }
            throw new UserStoreException(msg, ex);
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

    private void updateProperty(DB dbConnection, String userName, String property, String value, String profileName) throws UserStoreException {

        String mongoQuery=null;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_USER_PROPERTY);
        if(mongoQuery == null){

            throw new UserStoreException("The sql statement for add user property sql is null");
        }
        if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){

            updateStringValuesToDatabase(dbConnection,mongoQuery,value,userName,tenantId,property,profileName,tenantId);
        } else {

            updateStringValuesToDatabase(dbConnection, mongoQuery, value, userName, property, profileName);
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

    private void deleteProperty(DB dbConnection, String userName, String property, String profileName) throws UserStoreException {

        String mongoQuery = null;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_USER_PROPERTY);
        if(mongoQuery == null){

            throw new UserStoreException("The mongo statement for add user property mongo query is null");
        }
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            updateStringValuesToDatabase(dbConnection, mongoQuery, userName, tenantId, property,
                    profileName, tenantId);
        } else {
            updateStringValuesToDatabase(dbConnection, mongoQuery, userName, property, profileName);
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
            if(isShared){

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE);
            }else{

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
            }
            if(mongoQuery == null){

                throw new UserStoreException("The mongo statement for add user to role is null");
            }
            if(deletedUsers != null){

                if (isShared) {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                            roleName, tenantId,
                            deletedUsers, tenantId, tenantId, roleTenantId);
                } else {
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                deletedUsers, tenantId,
                                roleName, tenantId, tenantId);
                    } else {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                deletedUsers, roleName);
                    }
                }
            }
            if (newUsers != null) {
                if (isShared) {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery, roleName,
                            roleTenantId, newUsers, tenantId,
                            tenantId, roleTenantId);

                } else {
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                newUsers, tenantId,
                                roleName, tenantId,
                                tenantId);

                    } else {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                newUsers, roleName);
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

                if (roles.length > 0) {
                    mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.REMOVE_ROLE_FROM_USER);
                    if (mongoQuery == null) {
                        throw new UserStoreException(
                                "The mongo statement for remove user from role is null");
                    }
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                roles, tenantId, userName,
                                tenantId, tenantId);
                    } else {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery, roles, userName);
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
                if (roles.length > 0) {

                    realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
                }
                if (mongoQuery2 == null) {

                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
                }
                if (mongoQuery2 == null) {
                    throw new UserStoreException(
                            "The mongo statement for add user to role is null");
                } else {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, newRoles, userName);
                }
                MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                        roles, tenantId,
                        userName, tenantId,
                        tenantId);


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

	protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Getting roles of user: " + userName + " with filter: " + filter);
        }
        String mongoQuery = null;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USER_ROLE);
        List<String> roles = new ArrayList<String>();
        String[] names;
        if(mongoQuery == null){
            throw new UserStoreException("The mongo statement for retrieving user roles is null");
        }
        if(mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)){
            names = getStringValuesFromDatabase(mongoQuery, userName, tenantId, tenantId, tenantId);
        }
        else {
            names = getStringValuesFromDatabase(mongoQuery, userName);
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
	}

    private String[] getStringValuesFromDatabase(String mongoQuery, Object... params)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + mongoQuery);
            for (int i = 0; i < params.length; i++) {
                Object param = params[i];
                log.debug("Input value: " + param);
            }
        }

        String[] values = new String[0];
        MongoPreparedStatement prepStmt = null;
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            values = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection,mongoQuery);
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

        if (shared && isSharedGroupEnabled()) {
            doAddSharedRole(roleName, userList);
        }
        DB dbConnection = null;
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, roleName, tenantId);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, roleName);
            }
            if (userList != null) {

                String mongoQuery2 = null;
                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY);
                if (mongoQuery2 == null) {
                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE);
                }
                if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                            userList, tenantId, roleName, tenantId, tenantId);
                }else {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, userList, roleName);
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
        try{

            dbConnection = loadUserStoreSpacificDataSoruce();
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, roleName, tenantId);
            }else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, roleName);
            }

            if (userList != null) {

                String mongoQuery2 = null;
                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
                if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                            userList, tenantId, roleName, tenantId, tenantId);
                }else {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, userList, roleName);
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

    protected void doDeleteRole(String roleName) throws UserStoreException {

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
            if(mongoQuery1.contains(UserCoreConstants.UM_TENANT_COLUMN)){

                this.updateStringValuesToDatabase(dbConnection, mongoQuery1, roleName, tenantId,
                        tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery2, roleName, tenantId);
            }else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery1, roleName);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery2, roleName);
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

        if (isExistingRole(newRoleName)) {
            throw new UserStoreException("Role name: " + newRoleName
                    + " in the system. Please pick another role name.");
        }
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_ROLE_NAME);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for update role name is null");
        }
        DB dbConnection = null;
        try{

            roleName = ctx.getRoleName();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, newRoleName, roleName,
                        tenantId);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, newRoleName, roleName);
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
        DBCursor cursor = null;
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
                cursor = prepStmt.find();
            }catch (MongoQueryException e) {
                String errorMessage =
                        "Error while fetching users according to filter : " + filter + " & max Item limit " +
                                ": " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
            while (cursor.hasNext()) {

                String name = cursor.next().get("UM_USER_NAME").toString();
                if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(name)) {
                    continue;
                }
                // append the domain if exist
                String domain = realmConfig
                        .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                name = UserCoreUtil.addDomainToName(name, domain);
                lst.add(name);
            }
            cursor.close();
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
        if (!ctx.isShared()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_IN_ROLE);
            if (mongoQuery == null) {
                throw new UserStoreException("The mongo statement for retrieving user roles is null");
            }
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                names = getStringValuesFromDatabase(mongoQuery, roleName, tenantId, tenantId, tenantId);
            } else {
                names = getStringValuesFromDatabase(mongoQuery, roleName);
            }
        }else if (ctx.isShared()) {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_IN_SHARED_ROLE);
            names = getStringValuesFromDatabase(mongoQuery, roleName);
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
        String[] names;
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            names = getStringValuesFromDatabase(mongoQuery, userName, tenantId, tenantId);
        } else {
            names = getStringValuesFromDatabase(mongoQuery, userName);
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

        return names;
	}

	public String[] getAllProfileNames() throws UserStoreException {
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROFILE_NAMES);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving profile names is null");
        }
        String[] names;
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            names = getStringValuesFromDatabase(mongoQuery, tenantId);
        } else {
            names = getStringValuesFromDatabase(mongoQuery);
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
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERID_FROM_USERNAME);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving ID is null");
        }
        int id = -1;
        DB dbConnection = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, username,
                        tenantId);
            } else {
                id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, username);
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
        String mongoQuery;
        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_TENANT_ID_FROM_USERNAME);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving ID is null");
        }
        int id = -1;
        DB dbConnection = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, username);
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

    public boolean isExistingRememberMeToken(String userName, String token)
            throws org.wso2.carbon.user.api.UserStoreException {
        boolean isValid = false;
       /* Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        String value = null;
        Date createdTime = null;
        try {
            dbConnection = getDBConnection();
            prepStmt = dbConnection.prepareStatement(HybridJDBCConstants.GET_REMEMBERME_VALUE_SQL);
            prepStmt.setString(1, userName);
            prepStmt.setInt(2, tenantId);
            rs = prepStmt.executeQuery();
            while (rs.next()) {
                value = rs.getString(1);
                createdTime = rs.getTimestamp(2);
            }
        } catch (SQLException e) {
            log.error("Using sql : " + HybridJDBCConstants.GET_REMEMBERME_VALUE_SQL);
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            DatabaseUtil.closeAllConnections(null, rs, prepStmt);
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
        }*/

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
}
