package org.wso2.carbon.mongodb.userstoremanager.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/*import org.osgi.framework.Bundle;
import org.osgi.framework.BundleEvent;
import org.osgi.framework.BundleListener;*/
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.base.CarbonContextHolderBase;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.internal.CarbonContextDataHolder;
import org.wso2.carbon.mongodb.db.MongoDBDefaultRealmService;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;


import java.io.File;
import java.lang.management.ManagementPermission;
/*import java.util.ArrayList;
import java.util.List;*/

/**
 * @scr.component name="mongodb.userstoremanager.dscomponent" immediate=true
 *
 */
public class MongoDBUserStoreDSComponent{

	private static final Log log = LogFactory.getLog(MongoDBUserStoreDSComponent.class);

    protected void activate(ComponentContext cc) throws Exception{
        // Need permissions in order to instantiate user core
       // CarbonContextHolderBase.getCurrentCarbonContextHolderBase();
        // Need permissions in order to instantiate user core
        SecurityManager secMan = System.getSecurityManager();
        if(secMan != null){
            secMan.checkPermission(new ManagementPermission("control"));
        }
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
        RealmService realmService = new MongoDBDefaultRealmService(cc.getBundleContext());
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

}
