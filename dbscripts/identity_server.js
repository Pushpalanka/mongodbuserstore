//This function is create to auto incrment purposes

db.system.js.save(

   {

     _id: "getNextSequence",

     value : function(name) { 

            

        var ret = db.COUNTERS.findAndModify(

          {

            query: { _id: name },

            update: { $inc: { seq: 1 } },

            new: true

          }

        );



        return ret.seq;

     }

   }

);

//above function will stored in system.js script in order to use it here i will load the script

db.loadServerScripts();

db.REG_CLUSTER_LOCK.insert({

     REG_LOCK_NAME: "test",

     REG_LOCK_STATUS: "",

     REG_LOCKED_TIME: Timestamp(),

     REG_TENANT_ID: 0

});

db.REG_CLUSTER_LOCK.createIndex({REG_LOCK_NAME: 5},{unique: true});

/*in every document which use getNextSequence() function first it need to add to the sequence manging table which is called counter

in here after that using it id you can call the function and get the next sequence

*/

db.COUNTERS.insert({

    _id: "REG_LOG",

    seq: 0

});

db.REG_LOG.insert({

    REG_LOG_ID: getNextSequence("REG_LOG"),

    REG_PATH: "",

    REG_USER_ID: "",

    REG_LOGGED_TIME: Timestamp(),

    REG_ACTION: 0,

    REG_ACTION_DATA: "",

    REG_TENANT_ID: 0

});

db.REG_LOG.createIndex({REG_LOG_ID: 16,REG_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_PATH_ID",

    seq: 0

});
db.REG_PATH.insert({
        REG_PATH_ID : getNextSequence("REG_PATH_ID"),
        REG_PATH_VALUE: "Put Register Path Value here",
        REG_PATH_PARENT_ID : 0,
        REG_TENANT_ID : 0
});

db.REG_PATH.createIndex({REG_PATH_VALUE: "hashed"});

db.REG_PATH.createIndex({REG_PATH_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_CONTENT_ID",

    seq: 0

});
db.REG_CONTENT.insert({
        REG_CONTENT_ID : getNextSequence('REG_CONTENT_ID'),
        REG_CONTENT_DATA: BinData(5,"test"),
        REG_TENANT_ID : 0
    });

db.REG_CONTENT.createIndex({REG_CONTENT_ID: 16,REG_TENANT_ID: 16},{unique: true});
db.REG_CONTENT_HISTORY.find();

db.COUNTERS.insert({

    _id: "REG_CONTENT_HISTORY",

    seq: 0

});
db.REG_CONTENT_HISTORY.insert({
     REG_CONTENT_ID: getNextSequence('REG_CONTENT_HISTORY'),
     REG_DELETED: 0,
     REG_TENANT_ID: 0
});

db.REG_CONTENT_HISTORY.createIndex({REG_CONTENT_ID: 16,REG_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_RESOURCE",

    seq: 0

});
db.REG_RESOURCE.insert({
   REG_PATH_ID: 1,
   REG_PATH: "Regstered Path",
   REG_VERSION: getNextSequence('REG_RESOURCE'),
   REG_MEDIA_TYPE: "",
   REG_CREATOR: "",
   REG_CREATED_TIME: Timestamp(),
   REG_LAST_UPDATOR: "",
   REG_LAST_UPDATED_TIME: Timestamp(),
   REG_DESCRIPTION: "",
   REG_CONTENT_ID: 1,
   REG_TENANT_ID: 0,
   REG_UUID: "" 
});

db.REG_RESOURCE.createIndex({REG_NAME: "hashed"});//here i created the one hash index since it not allow to create multiple hash indexes

db.REG_RESOURCE.createIndex({REG_VERSION: 16,REG_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_RESOURCE_HISTORY",

    seq: 0

});
db.REG_RESOURCE_HISTORY.insert({
   REG_PATH_ID: 1,
   REG_NAME: "Regstered Name",
   REG_VERSION: getNextSequence('REG_RESOURCE_HISTORY'),
   REG_MEDIA_TYPE: "",
   REG_CREATOR: "",
   REG_CREATED_TIME: Timestamp(),
   REG_LAST_UPDATOR: "",
   REG_LAST_UPDATED_TIME: Timestamp(),
   REG_DESCRIPTION: "",
   REG_CONTENT_ID: 1,
   REG_DELETED: 0,
   REG_TENANT_ID: 0,
   REG_UUID: "" 
});

db.REG_RESOURCE_HISTORY.createIndex({REG_NAME: "hashed"});

db.REG_RESOURCE_HISTORY.createIndex({REG_VERSION: 16,REG_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_COMMENT",

    seq: 0

});
db.REG_COMMENT.insert({
   REG_COMMENT_TEXT: "",
   REG_ID: getNextSequence("REG_COMMENT"),
   REG_USER_ID: "",
   REG_COMMENTED_TIME: Timestamp(),
   REG_TENANT_ID: 0
});

db.REG_COMMENT.createIndex({REG_ID: 16,REG_TENANT_ID: 16},{unique: true});
db.REG_COMMENT.find();
db.REG_RESOURCE_COMMENT.insert({
     REG_COMMENT_ID: 1,
     REG_VERSION: 1,    
     REG_PATH_ID: 1,
     REG_RESOURCE_NAME: "",
     REG_TENANT_ID: 0
});

db.REG_RESOURCE_COMMENT.createIndex({REG_PATH_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_RATING",

    seq: 0

});
db.REG_RATING.insert({
     REG_ID: getNextSequence("REG_RATING"),
     REG_RATING: 1,
     REG_USER_ID: "",
     REG_RATED_TIME: Timestamp(),
     REG_TENANT_ID: 0
});

db.REG_RATING.createIndex({REG_ID: 16,REG_TENANT_ID: 16},{unique: true});
db.REG_RESOURCE_RATING.insert({
    REG_RATING_ID: 1,
    REG_VERSION: 1,
    REG_PATH_ID: 1,
    REG_RESOURCE_NAME: "",
    REG_TENANT_ID: 0
});

db.REG_RESOURCE_RATING.createIndex({REG_VERSION: "hased"});

db.COUNTERS.insert({

    _id: "REG_TAG",

    seq: 0

});
db.REG_TAG.insert({
    REG_ID: getNextSequence("REG_TAG"),
    REG_TAG_NAME: "",
    REG_USER_ID:  "",
    REG_TAGGED_TIME: Timestamp(),
    REG_TENANT_ID: 0
});

db.REG_TAG.createIndex({REG_ID: 16,REG_TENANT_ID: 16},{unique: true});
db.REG_RESOURCE_TAG.insert({
    REG_TAG_ID: 1,
    REG_VERSION: 1,
    REG_PATH_ID: 1,
    REG_RESOURCE_NAME: "",
    REG_TENANT_ID: 0
});

db.REG_RESOURCE_TAG.createIndex({REG_VERSION: "hashed"});

db.COUNTERS.insert({

    _id: "REG_PROPERTY",

    seq: 0

});
db.REG_PROPERTY.insert({
    REG_ID: getNextSequence("REG_PROPERTY"),
    REG_NAME: "",
    REG_VALUE: "",
    REG_TENANT_ID: 0
});

db.REG_PROPERTY.createIndex({REG_ID: 16,REG_TENANT_ID: 16},{unique: true});
db.REG_RESOURCE_PROPERTY.insert({
    REG_PROPERTY_ID: 1,
    REG_VERSION: 1,
    REG_PATH_ID: 1,
    REG_RESOURCE_NAME: "",
    REG_TENANT_ID: 0
});

db.REG_RESOURCE_PROPERTY.createIndex({REG_PATH_ID: "hashed"});

db.COUNTERS.insert({

    _id: "REG_ASSOCIATION",

    seq: 0

});
db.REG_ASSOCIATION.insert({
    REG_ASSOCIATION_ID: getNextSequence("REG_ASSOCIATION"),
    REG_SOURCEPATH: "",
    REG_TARGETPATH: "",
    REG_ASSOCIATION_TYPE: "",
    REG_TENANT_ID: 0
});

db.REG_ASSOCIATION.createIndex({REG_ASSOCIATION_ID: 16,REG_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "REG_SNAPSHOT",

    seq: 0

});
db.REG_SNAPSHOT.insert({
    REG_SNAPSHOT_ID: getNextSequence("REG_SNAPSHOT"),
    REG_PATH_ID : 1,
    REG_RESOURCE_NAME: "",
    REG_RESOURCE_VIDS: BinData(5,"test"),
    REG_TENANT_ID: 0,
});

db.REG_SNAPSHOT.createIndex({REG_SNAPSHOT_ID: 16,REG_TENANT_ID: 16},{unique: true});

db.REG_SNAPSHOT.createIndex({REG_PATH_ID: "hashed"});

//user management tables will start from here

db.COUNTERS.insert({

    _id: "UM_TENANT",

    seq: 0

});
db.UM_TENANT.insert({
    UM_ID: getNextSequence("UM_TENANT"),
    UM_DOMAIN_NAME: "",
    UM_EMAIL: "",
    UM_ACTIVE: false,
    UM_CREATED_DATE: Timestamp(),
    UM_USER_CONFIG: BinData(5,"test")
});
db.UM_TENANT.createIndex({UM_ID: 16},{unique: true});
db.UM_TENANT.createIndex({UM_DOMAIN_NAME: 5},{unique: true});
db.UM_TENANT.find();

db.COUNTERS.insert({

    _id: "UM_DOMAIN",

    seq: 0

});
db.UM_DOMAIN.insert({
    UM_DOMAIN_ID: getNextSequence("UM_DOMAIN"),
    UM_DOMAIN_NAME: "",
    UM_TENANT_ID: 0
});
db.UM_DOMAIN.createIndex({UM_DOMAIN_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_DOMAIN.find();

db.COUNTERS.insert({

    _id: "UM_USER",

    seq: 0

});
db.UM_USER.insert({
     UM_ID: getNextSequence("UM_USER"), 
     UM_USER_NAME: "", 
     UM_USER_PASSWORD: "",
     UM_SALT_VALUE: "",
     UM_REQUIRE_CHANGE: false,
     UM_CHANGED_TIME: Timestamp(),
     UM_TENANT_ID: 0
});
db.UM_USER.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_USER.createIndex({UM_USER_NAME: 5},{unique: true});
db.UM_USER.find();

db.COUNTERS.insert({

    _id: "UM_SYSTEM_USER",

    seq: 0

});
db.UM_SYSTEM_USER.insert({
     UM_ID: getNextSequence("UM_SYSTEM_USER"), 
     UM_USER_NAME: "", 
     UM_USER_PASSWORD: "",
     UM_SALT_VALUE: "",
     UM_REQUIRE_CHANGE: false,
     UM_CHANGED_TIME: Timestamp(),
     UM_TENANT_ID: 0
});
db.UM_SYSTEM_USER.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_SYSTEM_USER.createIndex({UM_USER_NAME: 5},{unique: true});

db.COUNTERS.insert({

    _id: "UM_ROLE",

    seq: 0

});
db.UM_ROLE.insert({
     UM_ID: getNextSequence("UM_SYSTEM_USER"), 
     UM_ROLE_NAME: "",
     UM_TENANT_ID: 0,
     UM_SHARED_ROLE: false
});
db.UM_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_ROLE.createIndex({UM_ROLE_NAME: 5},{unique: true});

db.COUNTERS.insert({

    _id: "UM_MODULE",

    seq: 0

});
db.UM_MODULE.insert({
    UM_ID: getNextSequence("UM_MODULE"),
    UM_MODULE_NAME: ""
});
db.UM_MODULE.createIndex({UM_ID: 16},{unique: true});
db.UM_MODULE.createIndex({UM_MODULE_NAME: 5},{unique: true});
db.UM_MODULE_ACTIONS.insert({
   UM_ACTION: "ACT",
   UM_MODULE_ID: 1
});
db.UM_MODULE_ACTIONS.createIndex({UM_ACTION: 5,UM_MODULE_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_PERMISSION",

    seq: 0

});
db.UM_PERMISSION.insert({
    UM_ID : getNextSequence("UM_PERMISSION"), 
    UM_RESOURCE_ID: "", 
    UM_ACTION: "", 
    UM_TENANT_ID: 0, 
    UM_MODULE_ID: 1
});
db.UM_PERMISSION.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_PERMISSION.createIndex({UM_RESOURCE_ID: 5,UM_ACTION: 5});

db.COUNTERS.insert({

    _id: "UM_ROLE_PERMISSION",

    seq: 0

});
db.UM_ROLE_PERMISSION.insert({
    UM_ID: getNextSequence("UM_ROLE_PERMISSION"), 
    UM_PERMISSION_ID: 1, 
    UM_ROLE_NAME: "",
    UM_IS_ALLOWED: 0, 
    UM_TENANT_ID: 0,
    UM_DOMAIN_ID : 1
});
db.UM_ROLE_PERMISSION.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_ROLE_PERMISSION.createIndex({UM_PERMISSION_ID: 16,UM_ROLE_NAME: 5,UM_TENANT_ID: 16,UM_DOMAIN_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_USER_PERMISSION",

    seq: 0

});
db.UM_USER_PERMISSION.insert({
    UM_ID: getNextSequence("UM_USER_PERMISSION"), 
    UM_PERMISSION_ID: 1, 
    UM_USER_NAME: "",
    UM_IS_ALLOWED: 0,          
    UM_TENANT_ID: 0
});
db.UM_USER_PERMISSION.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_USER_ROLE",

    seq: 0

});
db.UM_USER_ROLE.insert({
    UM_ID: getNextSequence("UM_USER_ROLE"), 
    UM_ROLE_ID: 1, 
    UM_USER_ID: 1,
    UM_TENANT_ID: 0
});
db.UM_USER_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_USER_ROLE.createIndex({UM_USER_ID: 16,UM_ROLE_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_SHARED_USER_ROLE.insert({
    UM_ROLE_ID: 1,
    UM_USER_ID: 1,
    UM_USER_TENANT_ID: 0,
    UM_ROLE_TENANT_ID: 0   
});
db.UM_SHARED_USER_ROLE.createIndex({UM_USER_ID: 16,UM_ROLE_ID: 16,UM_USER_TENANT_ID: 16,UM_ROLE_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_ACCOUNT_MAPPING",

    seq: 0

});
db.UM_ACCOUNT_MAPPING.insert({
    UM_ID: getNextSequence("UM_ACCOUNT_MAPPING"),
    UM_USER_NAME: "",
    UM_TENANT_ID: 0,
    UM_USER_STORE_DOMAIN: "",
    UM_ACC_LINK_ID: 0
});
db.UM_ACCOUNT_MAPPING.createIndex({UM_ID: 16},{unique: true});
db.UM_ACCOUNT_MAPPING.createIndex({UM_USER_NAME: 5,UM_TENANT_ID: 16,UM_USER_STORE_DOMAIN: 5,UM_ACC_LINK_ID: 0},{unique: true});

db.COUNTERS.insert({

    _id: "UM_USER_ATTRIBUTE",

    seq: 0

});
db.UM_USER_ATTRIBUTE.insert({
    
        UM_ID: getNextSequence("UM_USER_ATTRIBUTE"), 
        UM_ATTR_NAME: "", 
        UM_ATTR_VALUE: "", 
        UM_PROFILE_ID: "", 
        UM_USER_ID: 1, 
        UM_TENANT_ID: 0
});
db.UM_USER_ATTRIBUTE.createIndex({UM_ID: 16,UM_TENANT_ID: 0},{unique: true});

db.COUNTERS.insert({

    _id: "UM_DIALECT",

    seq: 0

});
db.UM_DIALECT.insert({
        UM_ID: getNextSequence("UM_DIALECT"), 
        UM_DIALECT_URI: "", 
        UM_TENANT_ID: 0
});
db.UM_DIALECT.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_DIALECT.createIndex({UM_DIALECT_URI: 5,UM_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_CLAIM",

    seq: 0

});
db.UM_CLAIM.insert({
        UM_ID: getNextSequence("UM_CLAIM"), 
        UM_DIALECT_ID: 1, 
        UM_CLAIM_URI: "", 
        UM_DISPLAY_TAG: "", 
        UM_DESCRIPTION: "", 
        UM_MAPPED_ATTRIBUTE_DOMAIN: "",
        UM_MAPPED_ATTRIBUTE: "", 
        UM_REG_EX: "", 
        UM_SUPPORTED: 0, 
        UM_REQUIRED: 0, 
        UM_DISPLAY_ORDER: 1,
	UM_CHECKED_ATTRIBUTE: 1,
        UM_READ_ONLY: 1,
        UM_TENANT_ID: 0
});
db.UM_CLAIM.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_CLAIM.createIndex({UM_CLAIM_URI: 5,UM_DIALECT_ID: 16,UM_TENANT_ID: 16,UM_MAPPED_ATTRIBUTE_DOMAIN: 5},{unique: true});

db.COUNTERS.insert({

    _id: "UM_PROFILE_CONFIG",

    seq: 0

});
db.UM_PROFILE_CONFIG.insert({
    UM_ID : getNextSequence("UM_PROFILE_CONFIG"), 
    UM_DIALECT_ID: 1, 
    UM_PROFILE_NAME: "", 
    UM_TENANT_ID: 0 
});
db.UM_PROFILE_CONFIG.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_HYBRID_ROLE",

    seq: 0

});
db.UM_HYBRID_ROLE.insert({
   UM_ID: getNextSequence("UM_HYBRID_ROLE"),
   UM_ROLE_NAME: "",
   UM_TENANT_ID: 0
});
db.UM_HYBRID_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_HYBRID_USER_ROLE",

    seq: 0

});
db.UM_HYBRID_USER_ROLE.insert({
    UM_ID: getNextSequence("UM_HYBRID_USER_ROLE"),
    UM_USER_NAME: "",
    UM_ROLE_ID: 1,
    UM_TENANT_ID: 0,
    UM_DOMAIN_ID: 1
});
db.UM_HYBRID_USER_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_HYBRID_USER_ROLE.createIndex({UM_USER_NAME: 5,UM_ROLE_ID: 16,UM_TENANT_ID: 16,UM_DOMAIN_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_SYSTEM_ROLE",

    seq: 0

});
db.UM_SYSTEM_ROLE.insert({
    UM_ID: getNextSequence("UM_SYSTEM_ROLE"),
    UM_ROLE_NAME: "",
    UM_TENANT_ID: 0
});
db.UM_SYSTEM_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_SYSTEM_USER_ROLE",

    seq: 0

});
db.UM_SYSTEM_USER_ROLE.insert({
   UM_ID: getNextSequence("UM_SYSTEM_USER_ROLE"),
   UM_USER_NAME: "",
   UM_ROLE_ID: 1,
   UM_TENANT_ID: 0 
});
db.UM_SYSTEM_USER_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_SYSTEM_USER_ROLE.createIndex({UM_USER_NAME: 5,UM_ROLE_ID: 16,UM_TENANT_ID: 16},{unique: true});

db.COUNTERS.insert({

    _id: "UM_HYBRID_REMEMBER_ME",

    seq: 0

});
db.UM_HYBRID_REMEMBER_ME.insert({
   UM_ID: getNextSequence("UM_HYBRID_REMEMBER_ME"),
   UM_USER_NAME: "",
   UM_COOKIE_VALUE: "",
   UM_CREATED_TIME: Timestamp(),
   UM_TENANT_ID: 0
});
db.UM_HYBRID_REMEMBER_ME.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});