package org.wso2.carbon.mongodb.db;

import com.mongodb.DB;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.mongodb.dao.MongoDBUserStoreConfigDao;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.claim.builder.ClaimBuilder;
import org.wso2.carbon.user.core.common.RealmCache;
import org.wso2.carbon.user.core.config.RealmConfigXMLProcessor;
import org.wso2.carbon.user.core.config.TenantMgtXMLProcessor;
import org.wso2.carbon.user.core.profile.builder.ProfileConfigurationBuilder;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.api.TenantMgtConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.config.multitenancy.MultiTenantRealmConfigBuilder;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.xml.namespace.QName;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * Default realm service class for MongoDBUserStore.
 */
public class MongoDBDefaultRealmService implements RealmService {

    private RealmCache realmCache = RealmCache.getInstance();
    private Map<Integer, UserRealm> userRealmMap = new HashMap<Integer, UserRealm>();
    private BundleContext bc;
    private RealmConfiguration bootstrapRealmConfig;
    private TenantMgtConfiguration tenantMgtConfiguration;
    private DB dataSource;
    private TenantManager tenantManager;
    private UserRealm bootstrapRealm;
    private MultiTenantRealmConfigBuilder multiTenantBuilder = null;
    private static final String PRIMARY_TENANT_REALM = "primary";
    private static boolean isFirstInitialization = true;
    private static final Log log = LogFactory.getLog(MongoDBDefaultRealmService.class);

    private static final String DB_CHECK_SQL = "{'collection' : 'UM_USER'}";

    //map to store and pass the connections to database and ldap which are created in this class.
    private Map<String, Object> properties = new Hashtable<String, Object>();

    public MongoDBDefaultRealmService(BundleContext bc,RealmConfiguration realmConfiguration) throws Exception{

        if(null != null){
            this.bootstrapRealmConfig = null;
        }
        else{
            this.bootstrapRealmConfig = buildBootStrapRealmConfig();
        }
       // this.tenantMgtConfiguration = buildTenantMgtConfig(bc,this.bootstrapRealmConfig.getUserStoreProperty(UserCoreConstants.TenantMgtConfig.LOCAL_NAME_TENANT_MANAGER));
        this.tenantMgtConfiguration = buildTenantMgtConfig(bc);
        this.dataSource = MongoDatabaseUtil.getRealmDataSource(this.bootstrapRealmConfig);
        properties.put(UserCoreConstants.DATA_SOURCE,this.dataSource);
        initializeDatabase(this.dataSource);
        this.tenantManager = this.initializeTenantManger(this.tenantMgtConfiguration);
        this.tenantManager.setBundleContext(bc);
        //initialize existing partitions if applicable with the particular tenant manager.
        this.tenantManager.initializeExistingPartitions();
        // initializing the bootstrapRealm
        this.bc = bc;
        bootstrapRealm = initializeRealm(bootstrapRealmConfig, 0);
        Dictionary<String, String> dictionary = new Hashtable<String, String>();
        dictionary.put(UserCoreConstants.REALM_GENRE, UserCoreConstants.DELEGATING_REALM);
        if (bc != null) {
            // note that in a case of we don't run this in an OSGI envrionment
            // like checkin-client,
            // we need to avoid the registration of the service
            bc.registerService(UserRealm.class.getName(), bootstrapRealm, dictionary);
        }

    }

    public MongoDBDefaultRealmService(BundleContext bc) throws Exception{

        this(bc,null);
    }

    public MongoDBDefaultRealmService(RealmConfiguration realmConfiguration,TenantManager tenantManager) throws Exception{

        this.bootstrapRealmConfig = realmConfiguration;
        this.dataSource = MongoDatabaseUtil.getRealmDataSource(bootstrapRealmConfig);
        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);
        this.tenantManager = tenantManager;
        bootstrapRealm = initializeRealm(bootstrapRealmConfig, 0);
    }

    @SuppressWarnings("unchecked")
    private UserRealm initializeRealm(RealmConfiguration realmConfig, int tenantId) throws UserStoreException{

        ClaimBuilder.setBundleContext(bc);
        ProfileConfigurationBuilder.setBundleContext(bc);
        UserRealm userRealm;
        try {
            Class clazz = Class.forName(realmConfig.getRealmClassName());
            userRealm = (UserRealm) clazz.newInstance();
            userRealm.init(realmConfig, properties, tenantId);
        } catch (Exception e) {
            String msg = "Cannot initialize the realm.";
            log.error(msg, e);
            throw new UserStoreException(msg, e);
        }
        return userRealm;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private TenantManager initializeTenantManger(TenantMgtConfiguration tenantMgtConfiguration) throws Exception{

        TenantManager tenantManager;
        // read the tenant manager from tenant-mgt.xml
        //String className = configElement.getAttribute(new QName("class")).getAttributeValue();
        String className = tenantMgtConfiguration.getTenantManagerClass();
        Class clazz = Class.forName(className);

        Constructor constructor = clazz.getConstructor(OMElement.class, Map.class);
        /*put the tenantMgtConfiguration and realm configuration inside the property map that is
        passed to tenant manager constructor. These are mainly used by LDAPTenantManager*/
        properties.put(UserCoreConstants.TENANT_MGT_CONFIGURATION, tenantMgtConfiguration);
        properties.put(UserCoreConstants.REALM_CONFIGURATION, bootstrapRealmConfig);

        //tenant config OMElement passed to the constructor is not used anymore. Hence passing a null.
        Object newObject = constructor.newInstance(null, properties);
        tenantManager = (TenantManager) newObject;

        return tenantManager;
    }

    private void initializeDatabase(DB dataSource) throws Exception{

        String value = System.getProperty("setup");
        if (value != null) {
            MongoDBCreator databaseCreator = new MongoDBCreator(dataSource);
            try {
                //if (!databaseCreator.isDatabaseStructureCreated()) {
                    databaseCreator.createRegistryDatabase();
                ///} else {
                    log.info("Database already exists. Not creating a new database.");
                //}
            } catch (Exception e) {
                String msg = "Error in creating the database";
                throw new Exception(msg, e);
            }
        }
    }

    private TenantMgtConfiguration buildTenantMgtConfig(BundleContext bc) throws UserStoreException{

        TenantMgtXMLProcessor tenantMgtXMLProcessor = new TenantMgtXMLProcessor();
        tenantMgtXMLProcessor.setBundleContext(bc);
        return tenantMgtXMLProcessor.buildTenantMgtConfigFromFile("com.mongodb.DB");
    }

    private RealmConfiguration buildBootStrapRealmConfig() throws UserStoreException{

        OMElement parentElement = getConfigurationElement();
        OMElement realmElement = parentElement.getFirstChildWithName(new QName(
                UserCoreConstants.RealmConfig.LOCAL_NAME_REALM));
        RealmConfigXMLProcessor rmProcessor = new RealmConfigXMLProcessor();
        rmProcessor.setSecretResolver(parentElement);
        return rmProcessor.buildRealmConfiguration(realmElement);
    }

    private OMElement getConfigurationElement() throws UserStoreException{

        try {
            String userMgt = CarbonUtils.getUserMgtXMLPath();
            InputStream inStream;
            if (userMgt != null) {
                File userMgtXml = new File(userMgt);
                if (!userMgtXml.exists()) {
                    String msg = "Instance of a WSO2 User Manager has not been created. user-mgt.xml is not found.";
                    throw new FileNotFoundException(msg);
                }
                inStream = new FileInputStream(userMgtXml);
            } else {
                inStream = this.getClass().getClassLoader()
                        .getResourceAsStream("repository/conf/user-mgt.xml");
                if (inStream == null) {
                    String msg = "Instance of a WSO2 User Manager has not been created. user-mgt.xml is not found. Please set the carbon.home";
                    throw new FileNotFoundException(msg);
                }
            }

            StAXOMBuilder builder = new StAXOMBuilder(inStream);
            return builder.getDocumentElement();
        } catch (FileNotFoundException e) {
            log.error(e.getMessage(), e);
            throw new UserStoreException(e.getMessage(), e);
        }catch(Exception e){
            log.error(e.getMessage(), e);
            throw new UserStoreException(e.getMessage(), e);
        }
    }

    public UserRealm getUserRealm(RealmConfiguration tenantRealmConfig) throws UserStoreException {

        UserRealm userRealm;
        int tenantId = tenantRealmConfig.getTenantId();
        userRealm = (UserRealm) realmCache.getUserRealm(tenantId, PRIMARY_TENANT_REALM);
        if (userRealm == null && tenantId == 0) {
            userRealm = bootstrapRealm;
        }

        if (tenantId != 0) {
            MultiTenantRealmConfigBuilder realmConfigBuilder = getMultiTenantRealmConfigBuilder();
            if (realmConfigBuilder != null) {
                tenantRealmConfig = realmConfigBuilder.getRealmConfigForTenantToCreateRealm(
                        bootstrapRealmConfig, tenantRealmConfig, tenantId);
            }
        }

        if (userRealm == null) {
            synchronized (this) {
                userRealm = initializeRealm(tenantRealmConfig, tenantId);
                userRealmMap.put(Integer.valueOf(tenantId), userRealm);
            }
        } else {
            long existingRealmPersistedTime = -1L;
            long newRealmConfigPersistedTime = -1L;
            if (userRealm.getRealmConfiguration().getPersistedTimestamp() != null) {
                existingRealmPersistedTime = userRealm.getRealmConfiguration()
                        .getPersistedTimestamp().getTime();
            }
            if (tenantRealmConfig.getPersistedTimestamp() != null) {
                newRealmConfigPersistedTime = tenantRealmConfig.getPersistedTimestamp().getTime();
            }

            if (existingRealmPersistedTime != newRealmConfigPersistedTime) {
                // this is an update
                userRealm = initializeRealm(tenantRealmConfig, tenantId);
                synchronized (this) {
                    userRealmMap.put(Integer.valueOf(tenantId), userRealm);
                }
            }
        }
        return userRealm;
    }

    public RealmConfiguration getBootstrapRealmConfiguration() {
        return bootstrapRealmConfig;
    }

    public void setBootstrapRealmConfiguration(RealmConfiguration realmConfiguration) {
        this.bootstrapRealmConfig = realmConfiguration;
    }

    public TenantMgtConfiguration getTenantMgtConfiguration() {
        return tenantMgtConfiguration;
    }

    public UserRealm getBootstrapRealm() throws UserStoreException {
        return bootstrapRealm;
    }

    public TenantManager getTenantManager() {
        return this.tenantManager;
    }

    public void setTenantManager(org.wso2.carbon.user.api.TenantManager tenantManager) throws org.wso2.carbon.user.api.UserStoreException {
        setTenantManager((TenantManager) tenantManager);
    }

    public org.wso2.carbon.user.api.UserRealm getTenantUserRealm(int tenantId) throws org.wso2.carbon.user.api.UserStoreException {

        if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
            return bootstrapRealm;
        }

        org.wso2.carbon.user.api.UserRealm userRealm = getCachedUserRealm(tenantId);
        if (userRealm != null) {
            return userRealm;
        }
        try {
            if (tenantManager.getTenant(tenantId) != null) {

                Tenant tenant = tenantManager.getTenant(tenantId);
                RealmConfiguration tenantRealmConfig = tenant.getRealmConfig();
                MultiTenantRealmConfigBuilder realmConfigBuilder = getMultiTenantRealmConfigBuilder();
                if (realmConfigBuilder != null) {
                    tenantRealmConfig = realmConfigBuilder.getRealmConfigForTenantToCreateRealm(
                            bootstrapRealmConfig, tenantRealmConfig, tenantId);
                }
                userRealm = initializeRealm(tenantRealmConfig, tenantId);
                synchronized (this) {
                    realmCache.addToCache(tenantId, PRIMARY_TENANT_REALM, userRealm);
                }
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new org.wso2.carbon.user.api.UserStoreException(e.getMessage(), e);
        }
        return userRealm;
    }

    public Map<String, String> getCustomUserStore(int tenantId) throws UserStoreException {
        MongoDBUserStoreConfigDao dao = new MongoDBUserStoreConfigDao(dataSource);
        return dao.getCustomUserStoreConfiguration(tenantId);
    }

    public void addCustomUserStore(String realmName, String userStoreClassName,
                                   Map<String, String> properties, int tenantId)
            throws UserStoreException {
        try {
            MongoDBUserStoreConfigDao dao = new MongoDBUserStoreConfigDao(dataSource);
            dao.addCustomUserStoreConfiguration(properties, tenantId);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new UserStoreException(e.getMessage(), e);
        }
    }

    public void setTenantManager(TenantManager tenantManager) {

        this.tenantManager = tenantManager;
    }




    public MultiTenantRealmConfigBuilder getMultiTenantRealmConfigBuilder() throws UserStoreException {

        try {
            if (multiTenantBuilder == null) {
                String clazzName = bootstrapRealmConfig
                        .getRealmProperty("MultiTenantRealmConfigBuilder");
                if (clazzName != null) {
                    Class clazz = Class.forName(clazzName);
                    return (MultiTenantRealmConfigBuilder) clazz
                            .newInstance();
                }
                return null;
            } else {
                return multiTenantBuilder;
            }
        } catch (ClassNotFoundException e) {
            errorEncountered(e);
        } catch (InstantiationException e) {
            errorEncountered(e);
        } catch (IllegalAccessException e) {
            errorEncountered(e);
        }
        return null;
    }

    private void errorEncountered(Exception e) throws UserStoreException {
        String msg = "Exception while creating multi tenant builder " + e.getMessage();
        log.error(msg, e);
        throw new UserStoreException(msg, e);
    }

    public UserRealm getCachedUserRealm(int tenantId) throws UserStoreException {

        return userRealmMap.get(Integer.valueOf(tenantId));
    }

    public void clearCachedUserRealm(int tenantId) throws UserStoreException {

        realmCache.clearFromCache(tenantId, PRIMARY_TENANT_REALM);
    }
}
