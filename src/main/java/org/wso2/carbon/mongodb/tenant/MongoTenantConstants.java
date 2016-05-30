package org.wso2.carbon.mongodb.tenant;

/**
 * MongoDB Tenant Queries.
 */
public class MongoTenantConstants {

    public static final String ADD_TENANT_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_DOMAIN_NAME' : '?','UM_EMAIL' : '?','UM_CREATED_DATE' : '?','UM_USER_CONFIG' : '?'}";
    public static final String UPDATE_TENANT_CONFIG_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?','projection' : '{'$set' : '{'UM_USER_CONFIG' : '?'}'}'}";
    public static final String UPDATE_TENANT_MONGOQUERY = "{'collection' : 'UM_TENANT' ,'UM_ID' : '?','projection' : '{'$set' : '{'UM_DOMAIN_NAME' : '?','UM_EMAIL' : '?','UM_CREATED_DATE' : '?'}'}'";
    public static final String GET_TENANT_MONGOQUERY = "{'collection' : 'UM_TENANT' , 'UM_ID' : '?','projection' : '{'UM_CREATED_DATE' : '1','UM_ACTIVE' : '1','UM_USER_CONFIG' : '1','UM_ID' : '1','UM_DOMAIN_NAME' : '1','UM_EMAIL' : '1'}' }";
    public static final String GET_ALL_TENANTS_MONGOQUERY = "{'collection' : 'UM_TENANT','projection' : '{'UM_ID' : '1','UM_DOMAIN_NAME' : '1','UM_EMAIL' : '1','UM_CREATED_DATE' : '1','UM_ACTIVE' : '1'}','$orderby' : '{'age' : '1'}'}";
    public static final String GET_DOMAIN_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?','projection' : '{'UM_DOMAIN_NAME' : '1'}'}";
    public static final String GET_TENANT_ID_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_DOMAIN_NAME' : '?','projection' : '{'UM_ID' : '1'}'}";
    public static final String ACTIVATE_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?','projection' : '{'$set' : '{'UM_ACTIVE' : '?'}'}'}";
    public static final String DEACTIVATE_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?','projection' : '{'$set' : '{'UM_ACTIVE' : '0'}'}'}";
    public static final String IS_TENANT_ACTIVE_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?','projection' : '{'UM_ACTIVE' : '1'}'}";
    public static final String DELETE_TENANT_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?'}";
    public static final String GET_MATCHING_TENANT_IDS_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_DOMAIN_NAME' : '{'$regex' : '?'}','projection' : '{'UM_ID' : '1','UM_DOMAIN_NAME' : '1','UM_EMAIL' : '1','UM_CREATED_DATE' : '1','UM_ACTIVE' : '1'}'}";
    public static String DELETE_TENANT_STATUS_MONGOQUERY = "{'collection' : 'UM_TENANT','UM_ID' : '?','UM_ACTIVE' : '?'}";
}
