package org.wso2.carbon.mongodb.userstoremanager.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.mongodb.db.MongoDBDefaultRealmService;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;


import java.io.File;

/**
 * @scr.component name="mongodb.userstoremanager.dscomponent" immediate=true
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 */
public class MongoDBUserStoreDSComponent{

	private static final Log log = LogFactory.getLog(MongoDBUserStoreDSComponent.class);
    private static RealmService realmService;

    protected void activate(ComponentContext cc) throws Exception{

        CarbonContext.getThreadLocalCarbonContext();
        // Need permissions in order to instantiate user core
        SecurityManager secMan = System.getSecurityManager();
        // Read the SSL trust store configurations from the Security.TrustStore element of the
        // Carbon.xml
        ServerConfiguration config = ServerConfiguration.getInstance();
        String type = config.getFirstProperty("Security.TrustStore.Type");
        String password = config.getFirstProperty("Security.TrustStore.Password");
        String storeFile = new File(config.getFirstProperty("Security.TrustStore.Location")).
                getAbsolutePath();
        // set the SSL trust store System Properties
        System.setProperty("javax.net.ssl.trustStore", storeFile);
        System.setProperty("javax.net.ssl.trustStoreType", type);
        System.setProperty("javax.net.ssl.trustStorePassword", password);
        realmService = new MongoDBDefaultRealmService(cc.getBundleContext());
        MongoDBUserStoreManager userStoreManager = new MongoDBUserStoreManager(realmService.getBootstrapRealmConfiguration());
        cc.getBundleContext().registerService(UserStoreManager.class.getName(), userStoreManager, null);
        MongoDatabaseUtil.logDatabaseConnections();
        UserCoreUtil.setRealmService(realmService);
        log.info("MongoDB User Store bundle activated successfully..");
        System.out.println("Mongo Started");
    }

    protected void deactivate(ComponentContext cc) throws Exception{
        System.out.println("MongoDB Bundle Shutting down");
        if (log.isDebugEnabled()) {
            log.debug("MongoDB User Store Manager is deactivated ");
        }
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void setRealmService(RealmService rlmService) {
        realmService = rlmService;
    }

    protected void unsetRealmService(RealmService rlmService) {
        realmService = null;
    }

}
