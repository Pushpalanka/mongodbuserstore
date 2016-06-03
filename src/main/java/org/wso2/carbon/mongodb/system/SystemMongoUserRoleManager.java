package org.wso2.carbon.mongodb.system;

import com.mongodb.DB;
import com.mongodb.DBCursor;
import com.mongodb.WriteResult;
import org.apache.axis2.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.json.JSONObject;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.mongodb.util.MongoUserCoreUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.security.SecureRandom;

public class SystemMongoUserRoleManager {

    private static Log log = LogFactory.getLog(SystemMongoUserRoleManager.class);
    int tenantId;
    private DB dataSource;
    private static final String SHA_1_PRNG = "SHA1PRNG";

    public SystemMongoUserRoleManager(DB dataSource, int tenantId) throws UserStoreException {
        super();
        this.dataSource = dataSource;
        this.tenantId = tenantId;
        //persist system domain
        MongoUserCoreUtil.persistDomain(UserCoreConstants.SYSTEM_DOMAIN_NAME, this.tenantId,
                this.dataSource);
    }

    public void addSystemRole(String roleName, String[] userList,DB datasource) throws UserStoreException {

        DB dbConnection = null;
        try {
            Map<String,Object> map = new HashMap<String, Object>();
            dbConnection = datasource;
            map.put("UM_ROLE_NAME",roleName);
            map.put("UM_TENANT_ID",tenantId);
            if (!this.isExistingRole(roleName,dbConnection)) {
                MongoDatabaseUtil.updateDatabase(dbConnection, SystemMongoDBConstants.ADD_ROLE_SQL,
                        map);
            }
            if (userList != null) {
                String sql = SystemMongoDBConstants.ADD_USER_TO_ROLE_SQL;
                    MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection,sql,userList,roleName,tenantId,tenantId);
            }
        } catch (Exception e) {
            String errorMessage = "Error occurred while adding system role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public boolean isExistingRole(String roleName,DB dataSource) throws UserStoreException {

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        boolean isExisting = false;
        try {
            dbConnection = dataSource;
            prepStmt = new MongoPreparedStatementImpl(dbConnection,SystemMongoDBConstants.GET_ROLE_ID);
            prepStmt.setString("UM_ROLE_NAME", roleName);
            prepStmt.setInt("UM_TENANT_ID", tenantId);
            cursor = prepStmt.find();
            if (cursor.hasNext()) {
                int value = Integer.parseInt(cursor.next().get("UM_ID").toString());
                if (value > -1) {
                    isExisting = true;
                }
            }
            return isExisting;
        } catch (Exception e) {
            String errorMessage = "Error occurred while checking is existing role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public String[] getSystemRoles(DB dataSource) throws UserStoreException {

        String mongoStmt = SystemMongoDBConstants.GET_ROLES;
        DB dbConnection = null;
        try {
            dbConnection = dataSource;
            Map<String,Object> map = new HashMap<String, Object>();
            map.put("UM_TENANT_ID",tenantId);
            String[] roles = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection, mongoStmt,
                    map,false,false);
            return MongoUserCoreUtil.addDomainToNames(roles, UserCoreConstants.SYSTEM_DOMAIN_NAME);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting system roles";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public String[] getUserListOfSystemRole(String roleName,DB datasource) throws UserStoreException {

        String mongoStmt = SystemMongoDBConstants.GET_USER_LIST_OF_ROLE_SQL;
        DB dbConnection = null;
        try {
            dbConnection = datasource;
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection,SystemMongoDBConstants.GET_ROLE_ID);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            prepStmt.setString("UM_ROLE_NAME",roleName);
            DBCursor cursor = prepStmt.find();
            int roleId = 0;
            if(cursor.hasNext()){

                roleId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            }
            Map<String,Object> map = new HashMap<String, Object>();
            map.put("UM_ROLE_ID",roleId);
            map.put("UM_TENANT_ID",tenantId);
            String[] users = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection, mongoStmt,
                    map,false,false);
            return MongoUserCoreUtil.addDomainToNames(users, UserCoreConstants.SYSTEM_DOMAIN_NAME);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting user list of system role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public void updateUserListOfSystemRole(String roleName, String[] deletedUsers, String[] newUsers,DB datasource)
            throws UserStoreException {

        String mongoStmt1 = SystemMongoDBConstants.REMOVE_USER_FROM_ROLE_SQL;
        String mongoStmt2 = SystemMongoDBConstants.ADD_USER_TO_ROLE_SQL;
        DB dbConnection = null;
        try {
            dbConnection = datasource;
            if (deletedUsers != null && deletedUsers.length > 0) {
                MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, mongoStmt1, deletedUsers,
                        roleName, tenantId, tenantId);
            }
            if (newUsers != null && newUsers.length > 0) {
                    MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, mongoStmt2, newUsers,
                            roleName, tenantId, tenantId);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage = "Error occurred while updating user list of system role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public String[] getSystemRoleListOfUser(String userName,DB dataSource) throws UserStoreException {
        String mongoStmt = SystemMongoDBConstants.GET_ROLE_LIST_OF_USER_SQL;
        DB dbConnection = null;
        try {
            dbConnection = dataSource;
            Map<String,Object> map = new HashMap<String, Object>();
            map.put("UM_USER_NAME",userName);
            map.put("UM_TENANT_ID",tenantId);
            map.put("userRole.UM_TENANT_ID",tenantId);
            String[] roles = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection, mongoStmt,
                    map,true,false);
            return MongoUserCoreUtil.addDomainToNames(roles, UserCoreConstants.SYSTEM_DOMAIN_NAME);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting system role list of user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public void updateSystemRoleListOfUser(String user, String[] deletedRoles, String[] addRoles,DB dataSource)
            throws UserStoreException {

        String sqlStmt1 = SystemMongoDBConstants.REMOVE_ROLE_FROM_USER_SQL;
        String sqlStmt2 = SystemMongoDBConstants.ADD_ROLE_TO_USER_SQL;
        DB dbConnection = null;
        try {
            dbConnection = dataSource;
            if (deletedRoles != null && deletedRoles.length > 0) {
                MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt1, deletedRoles,
                        tenantId, user, tenantId);
            }
            if (addRoles != null && addRoles.length > 0) {
                    MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt2, addRoles,
                            tenantId, user, tenantId);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage = "Error occurred while getting system role list of user : " + user;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public boolean isUserInRole(String userName, String roleName,DB datasource) throws UserStoreException {

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        boolean isUserInRole = false;
        try {
            dbConnection = datasource;
            prepStmt = new MongoPreparedStatementImpl(dbConnection,SystemMongoDBConstants.GET_ROLE_ID);
            prepStmt.setString("UM_ROLE_NAME",roleName);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            if(cursor.hasNext()){

                int roleId = Integer.parseInt(cursor.next().get("UM_ID").toString());
                prepStmt = new MongoPreparedStatementImpl(dbConnection,SystemMongoDBConstants.IS_USER_IN_ROLE_SQL);
                prepStmt.setString("UM_USER_NAME",userName);
                prepStmt.setInt("UM_ROLE_ID",roleId);
                prepStmt.setInt("UM_TENANT_ID",tenantId);
                cursor = prepStmt.find();
                if(cursor.hasNext()){

                    int value = Integer.parseInt(cursor.next().get("UM_ROLE_ID").toString());
                    if(value != -1){
                        isUserInRole = true;
                    }
                }
            }
        } catch (Exception e) {
            String errorMessage = "Error occurred while checking is user : " + userName + " & in role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return isUserInRole;
    }

    public boolean isExistingSystemUser(String userName,DB dataSource) throws UserStoreException {

        DB dbConnection = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        boolean isExisting = false;
        try {
            dbConnection = dataSource;
            prepStmt = new MongoPreparedStatementImpl(dbConnection,SystemMongoDBConstants.GET_USER_ID_SQL);
            prepStmt.setString("UM_USER_NAME", userName);
            prepStmt.setInt("UM_TENANT_ID", tenantId);
            cursor = prepStmt.find();
            if (cursor.hasNext()) {
                int value = Integer.parseInt(cursor.next().get("UM_ID").toString());
                if (value > -1) {
                    isExisting = true;
                }
            }
            return isExisting;
        } catch (Exception e) {
            String errorMessage = "Error occurred while checking is existing system user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public void addSystemUser(String userName, Object credential,
                              String[] roleList,DB dataSource) throws UserStoreException {

        DB dbConnection = null;
        String password = (String) credential;
        try {
            dbConnection = dataSource;
            String sqlStmt1 = SystemMongoDBConstants.ADD_USER_SQL;

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

            password = this.preparePassword(password, saltValue);

            this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName, password,
                    saltValue, false, new Date(), tenantId);

            // add user to role.
            updateSystemRoleListOfUser(userName, null, roleList);

        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public String[] getSystemUsers(DB dataSource) throws UserStoreException {

        DB dbConnection = null;
        String mongoStmt = null;
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        String filter = "*";
        int maxItemLimit = 100;

        String[] systemsUsers = new String[0];
        try {

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();

            dbConnection = dataSource;

            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }
            mongoStmt = SystemMongoDBConstants.GET_SYSTEM_USER_FILTER_SQL;

            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoStmt);
            prepStmt.setString("UM_USER_NAME", filter);
            if (mongoStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }

            cursor = prepStmt.find();

            int i = 0;
            while (cursor.hasNext()) {
                if (i < maxItemLimit) {
                    String name = cursor.next().get("UM_USER_NAME").toString();
                    lst.add(name);
                } else {
                    break;
                }
                i++;
            }
            cursor.close();

            if (lst.size() > 0) {
                systemsUsers = lst.toArray(new String[lst.size()]);
            }
            Arrays.sort(systemsUsers);
            systemsUsers = UserCoreUtil.addDomainToNames(systemsUsers, UserCoreConstants.SYSTEM_DOMAIN_NAME);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting system users";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return systemsUsers;

    }

    private String preparePassword(String password, String saltValue) throws UserStoreException {
        try {
            String digestInput = password;
            if (saltValue != null) {
                digestInput = password + saltValue;
            }
            MessageDigest dgst = MessageDigest.getInstance("SHA-256");
            byte[] byteValue = dgst.digest(digestInput.getBytes());
            password = Base64.encode(byteValue);
            return password;
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "Error occurred while preparing password : " + password;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
    }

    private void updateStringValuesToDatabase(DB dbConnection, String mongoStmt,
                                              Object... params) throws UserStoreException {


        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Invalid data provided");
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i), (Integer) param);
                    } else if (param instanceof Date) {
                        //Timestamp timestamp = new Timestamp(((Date) param).getTime());
                        //prepStmt.setTimestamp(i + 1, timestamp);
                        prepStmt.setTimeStamp(keys.get(i), new BSONTimestamp((int)System.currentTimeMillis(),1));
                    } else if (param instanceof Boolean) {
                        prepStmt.setBoolean(keys.get(i), (Boolean) param);
                    }
                }
            }
            WriteResult result = prepStmt.update();
            if (result.getN() == 0) {
                log.info("No rows were updated");
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed querry is " + mongoStmt + " and number of updated rows :: "
                        + result.getN());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeConnection(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    public void updateSystemRoleListOfUser(String user, String[] deletedRoles, String[] addRoles)
            throws UserStoreException {

        String sqlStmt1 = SystemMongoDBConstants.REMOVE_ROLE_FROM_USER_SQL;
        String sqlStmt2 = SystemMongoDBConstants.ADD_ROLE_TO_USER_SQL;
        DB dbConnection = null;
        try {
            dbConnection = dataSource;
            if (deletedRoles != null && deletedRoles.length > 0) {
                MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt1, deletedRoles,
                        tenantId, user, tenantId);
            }
            if (addRoles != null && addRoles.length > 0) {
                    MongoDatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt2, addRoles,
                            tenantId, user, tenantId);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage = "Error occurred while getting system role list of user : " + user;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private static List<String> getKeys(JSONObject stmt){

        int index = 0;
        List<String> keys=new ArrayList<String>();
        Iterator<String> keysfind = stmt.keys();
        while(keysfind.hasNext()){
            String key = keysfind.next();
            try{
                JSONObject value = stmt.getJSONObject(key);
                getKeys(value);
            }catch(Exception e){
                if(stmt.get(key).equals("?")){
                    index++;
                    keys.add(index,stmt.get(key).toString());
                }
            }
        }
        return keys;
    }
}
