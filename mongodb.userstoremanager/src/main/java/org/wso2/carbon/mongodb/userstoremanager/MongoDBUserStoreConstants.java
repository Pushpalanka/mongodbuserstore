package org.wso2.carbon.mongodb.userstoremanager;

import java.util.ArrayList;

import org.wso2.carbon.user.api.Property;

public class MongoDBUserStoreConstants {

	 public static final ArrayList<Property> CUSTOM_UM_MANDATORY_PROPERTIES = new ArrayList<Property>();
	    public static final ArrayList<Property> CUSTOM_UM_OPTIONAL_PROPERTIES = new ArrayList<Property>();
	    public static final ArrayList<Property> CUSTOM_UM_ADVANCED_PROPERTIES = new ArrayList<Property>();


	    private static void setProperty(String name, String displayName, String value, String description) {
	        Property property = new Property(name, value, displayName + "#" +description, (Property[])null);
	        CUSTOM_UM_OPTIONAL_PROPERTIES.add(property);

	    }

	    private static void setMandatoryProperty(String name, String displayName, String value, String description) {
	        Property property = new Property(name, value, displayName + "#" +description, (Property[])null);
	        CUSTOM_UM_MANDATORY_PROPERTIES.add(property);

	    }

	    private static void setAdvancedProperty(String name, String displayName, String value, String description) {
	        Property property = new Property(name, value, displayName + "#" +description, (Property[])null);
	        CUSTOM_UM_ADVANCED_PROPERTIES.add(property);

	    }

	    static {
	        setMandatoryProperty("ServiceURL", "Service URL", "mongodb://localhost:27017", "location of webservice");
	        setMandatoryProperty("Username", "User Name",  "root", "User Name to connect to mongodb (if provided)");
	        setMandatoryProperty("Password", "Enable Password", "", "Password to connect to mongodb server (if provided any)");
	        setProperty("db_name","Database Name","","Give your database name if you want to install user store other than default database");
	    }
}
