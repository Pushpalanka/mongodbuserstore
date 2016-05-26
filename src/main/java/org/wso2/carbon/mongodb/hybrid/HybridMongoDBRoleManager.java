package org.wso2.carbon.mongodb.hybrid;

import com.mongodb.DB;
import com.mongodb.DBCursor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.query.MongoQueryException;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBRealmConstants;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.authorization.AuthorizationCache;
import org.wso2.carbon.user.core.common.UserRolesCache;
import org.wso2.carbon.user.core.constants.UserCoreDBConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Hybrid Role Manager Class All Hybrid Role Configuration included.
 */
public class HybridMongoDBRoleManager {

    private static Log log = LogFactory.getLog(MongoDBUserStoreManager.class);
    private final int DEFAULT_MAX_ROLE_LIST_SIZE = 1000;
    private final int DEFAULT_MAX_SEARCH_TIME = 1000;
    protected UserRealm userRealm = null;
    protected UserRolesCache userRolesCache = null;
    int tenantId;
    private DB dataSource;
    private RealmConfiguration realmConfig;
    private String isCascadeDeleteEnabled;
    private boolean userRolesCacheEnabled = true;
    private static final String APPLICATION_DOMAIN = "Application";
    private static final String WORKFLOW_DOMAIN = "Workflow";

    public HybridMongoDBRoleManager(DB dataSource, int tenantId, RealmConfiguration realmConfig,
                                    UserRealm realm) throws UserStoreException {
        super();
        this.dataSource = dataSource;
        this.tenantId = tenantId;
        this.realmConfig = realmConfig;
        this.isCascadeDeleteEnabled = realmConfig.getRealmProperty(UserCoreDBConstants.CASCADE_DELETE_ENABLED);
        this.userRealm = realm;
        //persist internal domain
        HybridMongoDBRoleManager.persistDomain(UserCoreConstants.INTERNAL_DOMAIN, tenantId, dataSource,realmConfig);
        HybridMongoDBRoleManager.persistDomain(APPLICATION_DOMAIN, tenantId, dataSource,realmConfig);
        HybridMongoDBRoleManager.persistDomain(WORKFLOW_DOMAIN, tenantId, dataSource,realmConfig);

    }

    public static void persistDomain(String domain, int tenantId, DB dataSource,RealmConfiguration realmConfig) throws UserStoreException {

        DB dbConnection = null;
        try{

            String mongoStatement = MongoDBRealmConstants.ADD_DOMAIN_MONGO_QUERY;
            if(domain != null){
                domain = domain.toUpperCase();
            }
            if(!isExistingDomain(domain, tenantId, dataSource)){

                dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
                Map<String,Object> map = new HashMap<String, Object>();
                map.put("UM_DOMAIN_NAME",domain);
                map.put("UM_TENANT_ID",tenantId);
                MongoDatabaseUtil.updateDatabase(dbConnection,mongoStatement,map);
            }
        }catch(UserStoreException e){

            String errorMessage =
                    "Error occurred while checking is existing domain : " + domain + " for tenant : " + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }catch(Exception e){

            String errorMessage =
                    "DB error occurred while persisting domain : " + domain + " & tenant id : " + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }finally{

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private static boolean isExistingDomain(String domain, int tenantId, DB dataSource) throws UserStoreException{

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        boolean isExisting = false;

        try {
            dbConnection = dataSource;
            prepStmt = new MongoPreparedStatementImpl(dbConnection,MongoDBRealmConstants.IS_DOMAIN_EXISTS_MONGO_QUERY);
            if (domain != null) {
                domain = domain.toUpperCase();
            }
            prepStmt.setString("UM_DOMAIN_NAME", domain);
            prepStmt.setInt("UM_TENANT_ID", tenantId);
            cursor = prepStmt.find();
            if (cursor.hasNext()) {
                isExisting = true;
            }
            return isExisting;
        } catch (MongoQueryException e) {
            String errorMessage =
                    "DB error occurred while checking is existing domain : " + domain + " & tenant id : " + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * @param roleName Domain-less role
     * @param userList Domain-aware user list
     * @throws UserStoreException
     */
    public void addHybridRole(String roleName, String[] userList) throws UserStoreException {

        DB dbConnection = null;
        try{
            Map<String,Object> map = new HashMap<String, Object>();
            String primaryDomainName = getMyDomainName();
            map.put("UM_ROLE_NAME",roleName);
            map.put("UM_TENANT_ID",tenantId);
            if (primaryDomainName != null) {
                primaryDomainName = primaryDomainName.toUpperCase();
            }
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            if(!isExistingRole(roleName)){
                MongoDatabaseUtil.updateDatabase(dbConnection, HybridMongoDBConstants.ADD_ROLE_MONGO_QUERY,map);
            }
            else {
                throw new UserStoreException("Role name: " + roleName
                        + " in the system. Please pick another role name.");
            }
            if (userList != null) {
                String sql = HybridMongoDBConstants.ADD_USER_TO_ROLE_MONGO_QUERY;
                MongoDatabaseUtil.udpateUserRoleMappingInBatchModeForInternalRoles(dbConnection,
                            sql, primaryDomainName, userList, roleName, tenantId, tenantId, tenantId);

            }
        }catch(MongoQueryException e){

            String errorMessage = "Error occurred while adding hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }catch(UserStoreException e){

            String errorMessage = "Error occurred while adding hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
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

    /**
     * @param tenantID
     */
    protected void clearUserRolesCacheByTenant(int tenantID) {
        if (userRolesCache != null) {
            userRolesCache.clearCacheByTenant(tenantID);
            AuthorizationCache authorizationCache = AuthorizationCache.getInstance();
            authorizationCache.clearCacheByTenant(tenantID);
        }
    }

    /**
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public boolean isExistingRole(String roleName) throws UserStoreException {

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        boolean isExisting = false;
        try{

            prepStmt = new MongoPreparedStatementImpl(dbConnection,HybridMongoDBConstants.GET_ROLE_ID);
            prepStmt.setString("UM_ROLE_NAME",roleName);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            cursor = prepStmt.find();
            if(cursor.hasNext()){

                int value = Integer.parseInt(cursor.next().get("UM_ID").toString());
                if(value > -1){
                    isExisting = true;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Is roleName: " + roleName + " Exist: " + isExisting + " TenantId: " + tenantId);
            }
        }catch(MongoQueryException e){

            String errorMessage = "Error occurred while checking is existing role for role name : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        return isExisting;
    }

    /**
     * @param filter
     * @return
     * @throws UserStoreException
     */
    public String[] getHybridRoles(String filter) throws UserStoreException {

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;

        String mongoStmt = HybridMongoDBConstants.GET_ROLES_MONGO_QUERY;
        int maxItemLimit = UserCoreConstants.MAX_USER_ROLE_LIST;
        int searchTime = UserCoreConstants.MAX_SEARCH_TIME;

        try {
            maxItemLimit = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_ROLE_LIST));
        } catch (Exception e) {
            maxItemLimit = DEFAULT_MAX_ROLE_LIST_SIZE;
        }

        try {
            searchTime = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = DEFAULT_MAX_SEARCH_TIME;
        }

        try {
            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoStmt);
            prepStmt.setString("UM_ROLE_NAME",filter);
            if(mongoStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)){
                prepStmt.setInt("UM_TENANT_ID",tenantId);
            }
            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }
            List<String> filteredRoles = new ArrayList<String>();

            try {
                cursor = prepStmt.find();
            } catch (MongoQueryException e) {
                log.error("Error while retrieving roles from Internal JDBC role store", e);
                // May be due time out, therefore ignore this exception
            }

            if (cursor != null) {
                while (cursor.hasNext()) {
                    String name = cursor.next().get("UM_ROLE_NAME").toString();
                    // Append the domain
                    if (!name.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
                        name = UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR
                                + name;
                    }
                    filteredRoles.add(name);
                }
            }
            return filteredRoles.toArray(new String[filteredRoles.size()]);
        }catch (Exception e){

            String errorMessage = "Error occurred while getting hybrid roles from filter : " + filter;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public String[] getUserListOfHybridRole(String roleName) throws UserStoreException{

        if (UserCoreUtil.isEveryoneRole(roleName, realmConfig)) {
            return userRealm.getUserStoreManager().listUsers("*", -1);
        }

        String mongoStmt = HybridMongoDBConstants.GET_USER_LIST_OF_ROLE_MONGO_QUERY;
        DB dbConnection = null;
        try {
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            String[] names = MongoDatabaseUtil.getStringValuesFromDatabaseForInternalRoles(dbConnection, mongoStmt,
                    roleName, tenantId, tenantId);
            return names;
        } catch (MongoQueryException e) {
            String errorMessage = "Error occurred while getting user list from hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * @param roleName
     * @param deletedUsers
     * @param newUsers
     * @throws UserStoreException
     */
    public void updateUserListOfHybridRole(String roleName, String[] deletedUsers, String[] newUsers)
            throws UserStoreException {

        String mongoStmt1 = HybridMongoDBConstants.REMOVE_USER_FROM_ROLE_MONGO_QUERY;
        String mongoStmt2 = HybridMongoDBConstants.ADD_USER_TO_ROLE_MONGO_QUERY;
        DB dbConnection = null;
        try{

            // ########### Domain-less Roles and Domain-aware Users from here onwards #############
            String primaryDomainName = getMyDomainName();

            if (primaryDomainName != null) {
                primaryDomainName = primaryDomainName.toUpperCase();
            }
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);

            if (deletedUsers != null && deletedUsers.length > 0) {
                MongoDatabaseUtil.udpateUserRoleMappingInBatchModeForInternalRoles(
                        dbConnection, mongoStmt1, primaryDomainName, deletedUsers,
                        roleName, tenantId, tenantId, tenantId);
                // authz cache of deleted users from role, needs to be updated
                for (String deletedUser : deletedUsers) {
                    userRealm.getAuthorizationManager().clearUserAuthorization(deletedUser);
                }
            }

            if (newUsers != null && newUsers.length > 0) {
                MongoDatabaseUtil.udpateUserRoleMappingInBatchModeForInternalRoles(dbConnection,
                            mongoStmt2, primaryDomainName, newUsers, roleName, tenantId, tenantId, tenantId);
            }

        }catch(MongoQueryException e){

            String errorMessage = "Error occurred while updating user list of hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);

        }catch(UserStoreException e){

            String errorMessage = "Error occurred while updating user list of hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);

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

    /**
     * @param userName
     * @return
     * @throws UserStoreException
     */
    public String[] getHybridRoleListOfUser(String userName, String filter) throws UserStoreException {

        String getRoleListOfUserSQLConfig = realmConfig.getRealmProperty(HybridMongoDBConstants.GET_ROLE_LIST_OF_USER);
        String mongoStmt;
        mongoStmt = HybridMongoDBConstants.GET_ROLE_LIST_OF_USER_MONGO_QUERY;
        if (getRoleListOfUserSQLConfig != null && !getRoleListOfUserSQLConfig.equals("")) {
            mongoStmt = getRoleListOfUserSQLConfig;
        }
        DB dbConnection = null;
        try{

            userName = UserCoreUtil.addDomainToName(userName, getMyDomainName());
            String domain = UserCoreUtil.extractDomainFromName(userName);
            // ########### Domain-less Roles and Domain-aware Users from here onwards #############
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            if(domain != null){
                domain = domain.toUpperCase();
            }
            String[] roles = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection, mongoStmt,
                    UserCoreUtil.removeDomainFromName(userName), tenantId, tenantId, tenantId, domain);

            if (!CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
                // Adding everyone role
                if (roles == null || roles.length == 0) {
                    return new String[]{realmConfig.getEveryOneRoleName()};
                }
                List<String> allRoles = new ArrayList<String>();
                boolean isEveryone = false;
                for (String role : roles) {
                    if(!role.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
                        role = UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR
                                + role;
                    }
                    if (role.equals(realmConfig.getEveryOneRoleName())) {
                        isEveryone = true;
                    }
                    allRoles.add(role);
                }

                if (!isEveryone) {
                    allRoles.add(realmConfig.getEveryOneRoleName());
                }
                return allRoles.toArray(new String[allRoles.size()]);
            } else {
                return roles;
            }
        }catch (org.wso2.carbon.user.api.UserStoreException e) {

            String errorMessage = "Error occurred while getting hybrid role list of user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * @param user
     * @param deletedRoles
     * @param addRoles
     * @throws UserStoreException
     */
    public void updateHybridRoleListOfUser(String user, String[] deletedRoles, String[] addRoles)
            throws UserStoreException {

        String mongoStmt1 = HybridMongoDBConstants.REMOVE_ROLE_FROM_USER_MONGO_QUERY;
        String mongoStmt2 = HybridMongoDBConstants.ADD_ROLE_TO_USER_MONGO_QUERY;
        DB dbConnection = null;
        try {

            user = UserCoreUtil.addDomainToName(user, getMyDomainName());
            String domain = UserCoreUtil.extractDomainFromName(user);
            // ########### Domain-less Roles and Domain-aware Users from here onwards #############

            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            if (domain != null) {
                domain = domain.toUpperCase();
            }

            if (deletedRoles != null && deletedRoles.length > 0) {
                MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, mongoStmt1, deletedRoles,
                        tenantId, UserCoreUtil.removeDomainFromName(user), tenantId, tenantId, domain);
            }
            if (addRoles != null && addRoles.length > 0) {

                MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, mongoStmt2, addRoles,
                            tenantId, UserCoreUtil.removeDomainFromName(user), tenantId, tenantId, domain);
            }
        }catch(UserStoreException e) {

            String errorMessage = "Error occurred while updating hybrid role list of user : " + user;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);

        }catch(Exception e){

            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        // Authorization cache of user should also be updated if deleted roles are involved
        if (deletedRoles != null && deletedRoles.length > 0) {

            userRealm.getAuthorizationManager().clearUserAuthorization(user);
        }
    }


    /**
     * @param roleName
     * @throws UserStoreException
     */
    public void deleteHybridRole(String roleName) throws UserStoreException {

        // ########### Domain-less Roles and Domain-aware Users from here onwards #############

        if (UserCoreUtil.isEveryoneRole(roleName, realmConfig)) {
            throw new UserStoreException("Invalid operation");
        }

        DB dbConnection = null;
        try {

            Map<String,Object> map = new HashMap<String, Object>();
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,HybridMongoDBConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE_CONDITION_MONGO_QUERY);
            prepStmt.setString("UM_ROLE_NAME",roleName);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            DBCursor cursor = prepStmt.find();
            int roleId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            map.put("UM_ROLE_ID",roleId);
            map.put("UM_TENANT_ID",tenantId);
            MongoDatabaseUtil.deleteFromDatabase(dbConnection,
                        HybridMongoDBConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE_MONGO_QUERY, map);
            map.remove("UM_ROLE_ID");
            map.put("UM_ROLE_NAME",roleName);
            MongoDatabaseUtil.deleteFromDatabase(dbConnection, HybridMongoDBConstants.DELETE_ROLE_MONGO_QUERY,
                    map);
        }catch (org.wso2.carbon.user.api.UserStoreException e) {

            String errorMessage = "Error occurred while deleting hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (MongoQueryException e) {

            String errorMessage = "Error occurred while deleting hybrid role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        // also need to clear role authorization
        userRealm.getAuthorizationManager().clearRoleAuthorization(roleName);
    }

    /**
     * @param roleName
     * @param newRoleName
     * @throws UserStoreException
     */
    public void updateHybridRoleName(String roleName, String newRoleName) throws UserStoreException {

        // ########### Domain-less Roles and Domain-aware Users from here onwards #############

        if (this.isExistingRole(newRoleName)) {
            throw new UserStoreException("Role name: " + newRoleName
                    + " in the system. Please pick another role name.");
        }

        String mongoStmt = HybridMongoDBConstants.UPDATE_ROLE_NAME_MONGO_QUERY;
        if (mongoStmt == null) {
            throw new UserStoreException("The mongo statement for update hybrid role name is null");
        }

        DB dbConnection = null;
        try{
            Map<String,Object> map = new HashMap<String, Object>();
            map.put("UM_ROLE_NAME",roleName);
            map.put("UM_ROLE_NAME",newRoleName);
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            if (mongoStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID",tenantId);
                MongoDatabaseUtil.updateDatabase(dbConnection, mongoStmt, map);
            } else {
                MongoDatabaseUtil.updateDatabase(dbConnection, mongoStmt,map);
            }
            this.userRealm.getAuthorizationManager().resetPermissionOnUpdateRole(roleName,
                    newRoleName);
        }catch(Exception e){

            String errorMessage =
                    "Error occurred while updating hybrid role : " + roleName + " to new role : " + newRoleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * ##### This method is not used anywhere
     *
     * @param userName
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public boolean isUserInRole(String userName, String roleName) throws UserStoreException {
        // TODO
        String[] roles = getHybridRoleListOfUser(userName, "*");
        if (roles != null && roleName != null) {
            for (String role : roles) {
                if (UserCoreUtil.removeDomainFromName(role).equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * If a user is added to a hybrid role, that entry should be deleted upon deletion of the user.
     *
     * @param userName
     * @throws UserStoreException
     */
    public void deleteUser(String userName) throws UserStoreException{

        DB dbConnection = null;
        MongoPreparedStatement preparedStatement = null;

        userName = UserCoreUtil.addDomainToName(userName, getMyDomainName());
        String domain = UserCoreUtil.extractDomainFromName(userName);
        // ########### Domain-less Roles and Domain-aware Users from here onwards #############

        if (domain != null) {
            domain = domain.toUpperCase();
        }

        try {
            dbConnection = MongoDatabaseUtil.getRealmDataSource(realmConfig);
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,HybridMongoDBConstants.REMOVE_USER_MONGO_QUERY_CONDITION);
            prepStmt.setString("UM_DOMAIN_NAME",domain);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()){

                int domainId = Integer.parseInt(cursor.next().get("UM_ID").toString());
                preparedStatement = new MongoPreparedStatementImpl(dbConnection,HybridMongoDBConstants.REMOVE_USER_MONGO_QUERY);
                preparedStatement.setString("UM_USER_NAME", UserCoreUtil.removeDomainFromName(userName));
                preparedStatement.setInt("UM_TENANT_ID", tenantId);
                preparedStatement.setInt("UM_DOMAIN_ID",domainId);
                preparedStatement.remove();
            }
        } catch (MongoQueryException e) {
            String errorMessage = "Error occurred while deleting user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, preparedStatement);
        }
    }

    /**
     *
     */
    protected void initUserRolesCache() {

        String userRolesCacheEnabledString = (realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLES_CACHE_ENABLED));

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

    private String getMyDomainName() {

        return UserCoreUtil.getDomainName(realmConfig);
    }
}
