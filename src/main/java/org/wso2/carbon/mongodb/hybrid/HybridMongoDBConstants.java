package org.wso2.carbon.mongodb.hybrid;

/**
 * All Hybrid Constants in this class.
 */
public class HybridMongoDBConstants {

    public static final String GET_ROLE_LIST_OF_USER = "GetRoleListOfInternalUserSQL";

    public static final String ADD_ROLE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}";
    public static final String DELETE_ROLE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}";
    public static final String ON_DELETE_ROLE_REMOVE_USER_ROLE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_USER_ROLE','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}";
    public static final String ON_DELETE_ROLE_REMOVE_USER_ROLE_CONDITION_MONGO_QUERY = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : '1'}}";
    public static final String GET_ROLE_ID = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : '1'}}";

    //a single role name - multiple user names
    public static final String ADD_USER_TO_ROLE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_USER_ROLE','UM_USER_NAME' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_ID' : '?'}";
    public static final String USER_TO_ROLE_CONDITION_MONGO_QUERY = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : '1'}}";
    public static final String USER_DOMAIN_CONDITION_MONGO_QUERY = "{'collection' : 'UM_DOMAIN','UM_TENANT_ID' : '?','UM_DOMAIN_NAME' : '?','projection' : {'UM_DOMAIN_ID' : '1'}}";
    public static final String REMOVE_USER_FROM_ROLE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_USER_ROLE','UM_USER_NAME' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_ID' : '?'}";
    //a single user name - multiple role names
    public static final String ADD_ROLE_TO_USER_MONGO_QUERY = "{'collection':'UM_HYBRID_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_ID' : '?'}";
    //openedge
    //TODO: change to have domain id
    public static final String REMOVE_ROLE_FROM_USER_MONGO_QUERY = "{'collection' : 'UM_HYBRID_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_ID' : '?'}";

    public static final String GET_ROLES_MONGO_QUERY = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ROLE_NAME' : '1'}}";
    public static final String GET_USER_LIST_OF_ROLE_MONGO_QUERY = "{'collection' : 'UM_DOMAIN','role.UM_TENANT_ID' : '?','$lookup' : {'from' : 'UM_HYBRID_USER_ROLE','localField' : 'UM_DOMAIN_ID','foreignField' : 'UM_DOMAIN_ID','as' : 'role'},'projection' : {'UM_USER_NAME' : '1','UM_DOMAIN_NAME' : '1'}}";

    //public static final String GET_ROLE_LIST_OF_USER_SQL = "SELECT UM_ROLE_NAME FROM UM_HYBRID_USER_ROLE, UM_HYBRID_ROLE WHERE UM_USER_NAME=? AND UM_HYBRID_USER_ROLE.UM_ROLE_ID=UM_HYBRID_ROLE.UM_ID";

    public static final String GET_ROLE_LIST_OF_USER_MONGO_QUERY = "{'collection' : 'UM_HYBRID_USER_ROLE','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_NAME' : '?','roles.UM_TENANT_ID' : '?','roles.UM_DOMAIN_ID' : '?','$lookup' : {'from' : 'UM_HYBRID_ROLE','localField' : 'UM_ROLE_ID','foreignField' : 'UM_ID','as' : 'roles'}}";

    public static final String IS_USER_IN_ROLE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_USER_ROLE','UM_USER_NAME' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_ID' : '?'}";

    public static final String REMOVE_USER_MONGO_QUERY = "{'colletion' : 'UM_HYBRID_USER_ROLE','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','UM_DOMAIN_ID' : '?'}";

    public static final String REMOVE_USER_MONGO_QUERY_CONDITION = "{'collection' : 'UM_DOMAIN','UM_TENANT_ID' : '?','UM_DOMAIN_NAME' : '?','projection' : {'UM_ID' : '1'}}";

    public static final String UPDATE_ROLE_NAME_MONGO_QUERY = "{'collection' : 'UM_HYBRID_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_ROLE_NAME' : '?'}}}";

    public static final String ADD_REMEMBERME_VALUE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_REMEMBER_ME','UM_USER_NAME' : '?','UM_COOKIE_VALUE' : '?','UM_CREATED_TIME' : '?','UM_TENANT_ID' : '?'}";

    public static final String UPDATE_REMEMBERME_VALUE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_REMEMBER_ME','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_COOKIE_VALUE' : '?','UM_CREATED_TIME'}}}";

    public static final String GET_REMEMBERME_VALUE_MONGO_QUERY = "{'collection' : 'UM_HYBRID_REMEMBER_ME','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_CREATED_TIME' : '1','UM_COOKIE_VALUE' : '1'}}";
}
