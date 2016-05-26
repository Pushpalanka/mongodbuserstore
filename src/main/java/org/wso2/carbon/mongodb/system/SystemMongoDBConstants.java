package org.wso2.carbon.mongodb.system;

/**
 * Created by asantha on 5/25/16.
 */
public class SystemMongoDBConstants {

    public static final String GET_USER_ID_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_ID' : '1'}}}";
    public static final String ADD_USER_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_USER_NAME' : '?','UM_USER_PASSWORD' : '?','UM_SALT_VALUE' : '?','UM_REQUIRE_CHANGE' : '?','UM_CHANGED_TIME' : '?','UM_TENANT_ID' : '?'}";
    public static final String GET_SYSTEM_USER_FILTER_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_USER_NAME' ; '?','UM_TENANT_ID' : '?','$orderby' : {'UM_USER_NAME' : '1'},'projection' : {'UM_USER_NAME' : '1'}}";
    public static final String GET_USERID_FROM_USERNAME_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : '1'}}";
    public static final String GET_USERNAME_FROM_TENANT_ID_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_TENANT_ID' : '?','projection' : {'UM_USER_NAME' : '1'}}";
    public static final String GET_TENANT_ID_FROM_USERNAME_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_USER_NAME' : '?','projection' : {'UM_TENANT_ID' : '1'}}";
    public static final String DELETE_USER_SQL = "{'collection' : 'UM_SYSTEM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}";
    public static final String ADD_ROLE_SQL = "{'collection' : 'UM_SYSTEM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}";
    public static final String DELETE_ROLE_SQL = "{'collection' : 'UM_SYSTEM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}";
    public static final String ON_DELETE_ROLE_REMOVE_USER_ROLE_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}";
    public static final String ON_DELETE_ROLE_REMOVE_USER_ROLE_CONDITION = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : '1'}}";
    public static final String GET_ROLE_ID = "{'collection' : 'UM_SYSTEM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : '1'}}";

    //a single role name - multiple user names
    public static final String ADD_USER_TO_ROLE_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_USER_NAME' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}";

    public static final String REMOVE_USER_FROM_ROLE_SQL = "{'colletion' : 'UM_SYSTEM_USER_ROLE','UM_USER_NAME' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}";

    //a single user name - multiple role names
    public static final String ADD_ROLE_TO_USER_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}";

    public static final String REMOVE_ROLE_FROM_USER_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}";

    public static final String GET_ROLES = "{'collection' : 'UM_SYSTEM_ROLE','UM_TENANT_ID' : '?','projection' : {'UM_ROLE_NAME' : '1'}}";
    public static final String GET_USER_LIST_OF_ROLE_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?','projection' : {'UM_USER_NAME' : '1'}}";
    //public static final String GET_ROLE_LIST_OF_USER_SQL = "SELECT UM_ROLE_NAME FROM UM_SYSTEM_USER_ROLE, UM_SYSTEM_ROLE WHERE UM_USER_NAME=? AND UM_SYSTEM_USER_ROLE.UM_ROLE_ID=UM_SYSTEM_ROLE.UM_ID";

    public static final String GET_ROLE_LIST_OF_USER_SQL = "{'collection' : 'UM_SYSTEM_ROLE','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','userRole.UM_TENANT_ID' : '?','$lookup' : {'from' : 'UM_SYSTEM_USER_ROLE','localField' : 'UM_ID','foreignField' : 'UM_ROLE_ID','as' : 'userRole'},'projection' : {'UM_ROLE_NAME' : '1'}}";

    public static final String IS_USER_IN_ROLE_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_USER_NAME' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ROLE_ID' : '1'}}";

    public static final String REMOVE_USER_SQL = "{'collection' : 'UM_SYSTEM_USER_ROLE','UM_USER_NAME' : '?'}";

    public static final String UPDATE_ROLE_NAME_SQL = "{'collection' : 'UM_SYSTEM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_ROLE_NAME' : '?'}}}";

    public static final String ADD_REMEMBERME_VALUE_SQL = "{'collection' : 'UM_SYSTEM_REMEMBER_ME','UM_USER_NAME' : '?','UM_COOKIE_VALUE' : '?','UM_CREATED_TIME' : '?','UM_TENANT_ID' : '?'}";

    public static final String UPDATE_REMEMBERME_VALUE_SQL = "{'collection' : 'UM_SYSTEM_REMEMBER_ME','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_COOKIE_VALUE' : '?','UM_CREATED_TIME' : '?'}}}";

    public static final String GET_REMEMBERME_VALUE_SQL = "{'collection' : 'UM_SYSTEM_REMEMBER_ME','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_COOKIE_VALUE' : '1','UM_CREATED_TIME' : '1'}}";
}
