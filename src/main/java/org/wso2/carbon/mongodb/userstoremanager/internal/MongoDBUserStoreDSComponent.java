package org.wso2.carbon.mongodb.userstoremanager.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.user.api.UserStoreManager;


/**
 * @scr.component name="mongodb.userstoremanager.dscomponent" immediate=true
 *
 */

public class MongoDBUserStoreDSComponent {

	private static Log log = (Log) LogFactory.getLog(MongoDBUserStoreDSComponent.class);

    protected void activate(ComponentContext ctxt) throws Exception{

        MongoDBUserStoreManager userStoreManager = new MongoDBUserStoreManager();
        ctxt.getBundleContext().registerService(UserStoreManager.class.getName(), userStoreManager, null);
        log.info("MongoDB User Store bundle activated successfully..");
        System.out.println("Mongo Started");
    }

    protected void deactivate(ComponentContext ctxt) throws Exception{
        System.out.println("MongoDB Bundle Shutting down");
        if (log.isDebugEnabled()) {
            log.debug("MongoDB User Store Manager is deactivated ");
        }
    }
}
