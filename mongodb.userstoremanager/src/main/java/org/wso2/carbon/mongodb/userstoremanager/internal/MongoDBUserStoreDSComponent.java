package org.wso2.carbon.mongodb.userstoremanager.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="mongodb.userstoremanager.dscomponent" immediate=true
 */

public class MongoDBUserStoreDSComponent {

	private static Log log = (Log) LogFactory.getLog(MongoDBUserStoreDSComponent.class);
    private static RealmService realmService;

    protected void activate(ComponentContext ctxt) {

        MongoDBUserStoreManager userStoreManager = new MongoDBUserStoreManager();
        ctxt.getBundleContext().registerService(UserStoreManager.class.getName(), userStoreManager, null);
        log.info("MongoDB User Store bundle activated successfully..");
        System.out.println("Mongo Started");
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("MongoDB User Store Manager is deactivated ");
        }
    }

    protected void setRealmService(RealmService rlmService) {
          realmService = rlmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        realmService = null;
    }
    
    public static RealmService getRealmService() {
        return realmService;
    }
}
