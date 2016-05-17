package org.wso2.carbon.mongodb.userstoremanager;

import java.util.ArrayList;

import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.core.UserStoreConfigConstants;

public class MongoDBUserStoreConstants {

	 public static final ArrayList<Property> CUSTOM_UM_MANDATORY_PROPERTIES = new ArrayList<Property>();
	    public static final ArrayList<Property> CUSTOM_UM_OPTIONAL_PROPERTIES = new ArrayList<Property>();
	    public static final ArrayList<Property> CUSTOM_UM_ADVANCED_PROPERTIES = new ArrayList<Property>();


	    private static void setProperty(String name,String value, String description) {
	        Property property = new Property(name, value, description, null);
	        CUSTOM_UM_OPTIONAL_PROPERTIES.add(property);

	    }

	    private static void setMandatoryProperty(String name, String value, String description) {
	        Property property = new Property(name, value, description, null);
	        CUSTOM_UM_MANDATORY_PROPERTIES.add(property);

	    }

	    private static void setAdvancedProperty(String name, String value, String description) {
	        Property property = new Property(name, value,description, null);
	        CUSTOM_UM_ADVANCED_PROPERTIES.add(property);

	    }

	    static {
	        setMandatoryProperty(MongoDBRealmConstants.URL, "127.0.0.1", "location of webservice");
	        setMandatoryProperty(MongoDBRealmConstants.USER_NAME, "admin", "User Name to connect to mongodb (if provided)");
	        setMandatoryProperty(MongoDBRealmConstants.PASSWORD, "admin", "Password to connect to mongodb server (if provided any)");
			setProperty("PasswordDigest", "SHA-256", UserStoreConfigConstants.passwordHashMethodDescription);
			setProperty(UserStoreConfigConstants.readGroups, "true", UserStoreConfigConstants.readLDAPGroupsDescription);
			setProperty("ReadOnly", "false", "Indicates whether the user store of this realm operates in the user read only mode or not");
			setProperty("IsEmailUserName", "false", "Indicates whether Email is used as user name (apply when realm operates in read only mode).");
			setProperty("DomainCalculation", "default", "Can be either default or custom (apply when realm operates in read only mode)");
			setProperty("StoreSaltedPassword", "true", "Indicates whether to salt the password");
			setProperty(UserStoreConfigConstants.writeGroups, "true", UserStoreConfigConstants.writeGroupsDescription);
			setProperty("UserNameUniqueAcrossTenants", "false", "An attribute used for multi-tenancy");
			setProperty("PasswordJavaRegEx", "^[\\S]{5,30}$", "A regular expression to validate passwords");
			setProperty("PasswordJavaScriptRegEx", "^[\\S]{5,30}$", "The regular expression used by the font-end components for password validation");
			setProperty("UsernameJavaRegEx", "^[\\S]{5,30}$", "A regular expression to validate user names");
//        setProperty("UsernameJavaRegEx","^[^~!#$;%^*+={}\\\\|\\\\\\\\&lt;&gt;,\\\'\\\"]{3,30}$","A regular expression to validate user names");
			setProperty("UsernameJavaScriptRegEx", "^[\\S]{5,30}$", "The regular expression used by the font-end components for username validation");
			setProperty("RolenameJavaRegEx", "^[\\S]{5,30}$", "A regular expression to validate role names");
//        setProperty("RolenameJavaRegEx","^[^~!#$;%^*+={}\\\\|\\\\\\\\&lt;&gt;,\\\'\\\"]{3,30}$","A regular expression to validate role names");
			setProperty("RolenameJavaScriptRegEx", "^[\\S]{5,30}$", "The regular expression used by the font-end components for role name validation");
			setProperty(UserStoreConfigConstants.SCIMEnabled, "false", UserStoreConfigConstants.SCIMEnabledDescription);

			//Advanced Properties (No descriptions added for each property)
			setAdvancedProperty("SelectUserMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}", "");
			setAdvancedProperty("GetRoleListMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_TENANT_ID' : '?','projection':{'UM_ROLE_NAME' : '1','_id' : '0'}}", "");
			setAdvancedProperty("GetSharedRoleListMONGO_QUERY","{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_SHARED_ROLE' : '1','projection' : '{'UM_ROLE_NAME' : '1','UM_TENANT_ID' : '1','UM_SHARED_ROLE' : '1'}'}", "");
			setAdvancedProperty("UserFilterMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_USER_NAME' : '1','$orderby' : {'UM_USER_NAME' : '1'}}}", "");
			setAdvancedProperty("UserRoleMONGO_QUERY ", "{'collection' : 'UM_ROLE','UM_TENANT_ID' : '?','projection' : {'UM_ROLE_NAME' : '1'},'$lookup' : [{'from' : 'UM_USER_ROLE','localField' : 'UM_ID','foreignField' : 'UM_ROLE_ID','UM_TENANT_ID' : '?'},{'from' : 'UM_USER','localField' : 'UM_ID','foreignField' : 'UM_ROLE_ID','UM_TENANT_ID' : '?'}]}", "");
			setAdvancedProperty("UserSharedRoleMONGO_QUERY","{'collection' : 'UM_SHARED_USER_ROLE','user.UM_USER_NAME' : '?','UM_USER_TENANT_ID' : 'role.UM_TENANT_ID','UM_USER_TENANT_ID' : '?','$lookup' : '[{'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'user'},{'from' : 'UM_ROLE','localField' : 'UM_ROLE_ID','foreignField' : 'UM_ID','as' : 'role'}]'}","");

			setAdvancedProperty("IsRoleExistingMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : '{'UM_ID' : '1'}'}","");
			setAdvancedProperty("GetUserListOfRoleMONGO_QUERY","{'collection' : 'UM_USER','UM_TENANT_ID' : '?','role.UM_ROLE_NAME' : '?','role.UM_TENANT_ID' : '?','userRole.UM_TENANT_ID' : '?','projection' : {'UM_USER_NAME' : '1'},'$lookup' : '[{'from' : 'UM_USER_ROLE','localField' : 'UM_ID','foreignField' : 'UM_USER_ID','as' : 'userRole'},{'from' : 'UM_ROLE','localField' : 'UM_USER_ROLE.UM_ROLE_ID','foreignField' : 'UM_ROLE.UM_ID','as' : 'role'}]'}","");

			setAdvancedProperty("IsUserExistingMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : '{'UM_ID' : '1'}'}","");
			setAdvancedProperty("GetUserPropertiesForProfileMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?','users.UM_USER_NAME' : '?','users.UM_TENANT_ID' : '?','$lookup' : '{'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'users'}','projection' : '{'UM_ATTR_NAME' : '1','UM_PROFILE_VALUE' : '1'}'}","");
			setAdvancedProperty("GetUserPropertyForProfileMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?','users.UM_USER_NAME' : '?','users.UM_TENANT_ID' : '?','$lookup' : '{'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'users'},'projection' : '{'UM_ATTR_VALUE' : '1'}''}","");
			setAdvancedProperty("GetUserLisForPropertyMONGO_QUERY","{'collection' : 'UM_USER','attribute.UM_ATTR_NAME' : '?','attribute.UM_ATTR_VALUE' : '?','attribute.UM_ATTR_NAME' : '?','attribute.UM_PROFILE_ID' : '?','atrribute.UM_TENANT_ID' : '?','user.UM_TENANT_ID' : '?','$lookup' : '{'from' : 'UM_USER_ATTRIBUTE','localField' : 'UM_ID','foreignField' : 'UM_USER_ID','as' : 'attribute'}','projection' : '{'UM_USER_NAME' : '1'}'}","");

			setAdvancedProperty("GetProfileNamesMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_TENANT_ID' : '?','projection' : '{'UM_PROFILE_ID' : '1'}','distinct' : 'UM_PROFILE_ID'}","");
			setAdvancedProperty("GetUserProfileNamesMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','projection' : '{'UM_PROFILE_ID' : '?'}','distinct' : 'UM_PROFILE_ID'}","");
			setAdvancedProperty("GetUserIDFromUserNameMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : '{'UM_ID' : '1'}'}","");
			setAdvancedProperty("GetUserNameFromTenantIDMONGO_QUERY", "{'collection' : 'UM_USER','UM_TENANT_ID' : '?','projection' : '{'UM_USER_NAME' : '1'}'}","");
			setAdvancedProperty("GetTenantIDFromUserNameMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','projection' : '{'UM_TENANT_ID' : '?'}'}","");

			setAdvancedProperty("AddUserMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_USER_PASSWORD' : '?','UM_SALT_VALUE' : '?','UM_REQUIRE_CHANGE' : '?','UM_CHANGED_TIME' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("AddUserToRoleMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_USER_ID' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("AddRoleMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("AddSharedRoleMONGO_QUERY", "UPDATE UM_ROLE SET UM_SHARED_ROLE = ? WHERE UM_ROLE_NAME = ? AND UM_TENANT_ID = ?","");
			setAdvancedProperty("AddRoleToUserMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("AddSharedRoleToUserMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID' : '?','UM_USER_TENANT_ID' : '?','UM_ROLE_TENANT_ID' : '?'}","");

			setAdvancedProperty("RemoveUserFromSharedRoleMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID' : '?','UM_USER_TENANT_ID' : '?','UM_ROLE_TENANT_ID' : '?'}","");
			setAdvancedProperty("RemoveUserFromRoleMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_USER_ID' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}","");

			setAdvancedProperty("RemoveRoleFromUserMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID': '?','UM_TENANT_ID' : '?'}","");

			setAdvancedProperty("DeleteRoleMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("OnDeleteRoleRemoveUserRoleMappingMONGO_QUERY ", "{'collection' : 'UM_USER_ROLE','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}" ,"");
			setAdvancedProperty("DeleteUserMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("OnDeleteUserRemoveUserRoleMappingMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_USER_ID' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("OnDeleteUserRemoveUserAttributeMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?',UM_TENANT_ID : '?'}","");

			setAdvancedProperty("UpdateUserPasswordMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : '{'$set'  : '{'UM_USER_PASSWORD' : '?','UM_SALT_VALUE' : '?','UM_REQUIRE_CHANGE' : '?','UM_CHANGED_TIME' : '?'}'}'}","");
			setAdvancedProperty("UpdateRoleNameMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : '{'$set' : '{'UM_ROLE_NAME' : '?'}'}'}","");

			setAdvancedProperty("AddUserPropertyMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_ATTR_VALUE' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("UpdateUserPropertyMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?','projection' : '{$set' : '{'UM_ATTR_VALUE' : '?'}}'}","");
			setAdvancedProperty("DeleteUserPropertyMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?'}","");
			setAdvancedProperty("UserNameUniqueAcrossTenantsMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?'}","");

			setAdvancedProperty("IsDomainExistingMONGO_QUERY","{'collection' : 'UM_DOMAIN','UM_DOMAIN_NAME' : '?','UM_TENANT_ID' : '?','projection' : '{'UM_DOMAIN_ID' : '1'}'}","");

			setAdvancedProperty("AddDomainMONGO_QUERY", "{'collection' : 'UM_DOMAIN','UM_DOMAIN_NAME' : '?','UM_TENANT_ID' : '?'}","");

		}
}
