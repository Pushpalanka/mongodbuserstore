package org.wso2.carbon.mongodb.tenant;

import com.mongodb.*;
import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.query.MongoQueryException;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.TenantManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.config.RealmConfigXMLProcessor;
import org.wso2.carbon.user.core.tenant.TenantCache;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

import java.util.Map;

/**
 * MongoDB Tenant Manager
 */
public class MongoDBTenantManager implements TenantManager {

    DB dataSource;
    private static Log log = LogFactory.getLog(TenantManager.class);
    protected BundleContext bundleContext;

    /**
     * Map which maps tenant domains to tenant IDs
     *
     * Key - tenant domain, value - tenantId
     */
    private Map tenantDomainIdMap = new ConcurrentHashMap<String, Integer>();

    /**
     * This is the reverse of the tenantDomainIdMap. Key - tenantId, value - tenant domain
     */
    private Map tenantIdDomainMap = new ConcurrentHashMap<Integer, String>();

    protected TenantCache tenantCacheManager = TenantCache.getInstance();

    public MongoDBTenantManager(OMElement omElement, Map<String, Object> properties) throws Exception {
        this.dataSource = (DB) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            throw new Exception("Data Source is null");
        }
        this.tenantCacheManager.clear();
    }

    public MongoDBTenantManager(DB dataSource) {
        this.dataSource = dataSource;
    }
    public int addTenant(Tenant tenant) throws UserStoreException {

        MongoPreparedStatement prepStmt=null;
        int id = 0;
        try{
            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.ADD_TENANT_MONGOQUERY);
            id = getCollectionSequence("UM_TENANT",dataSource);
            prepStmt.setInt("UM_ID",id);
            prepStmt.setString("UM_EMAIL",tenant.getEmail());
            prepStmt.setString("UM_DOMAIN_NAME",tenant.getDomain().toLowerCase());
            Date createdTime = tenant.getCreatedDate();
            int createdTimeMs;
            if (createdTime == null) {
                createdTimeMs = (int)System.currentTimeMillis();
            } else {
                createdTimeMs = (int)createdTime.getTime();
            }
            prepStmt.setTimeStamp("UM_CREATED_DATE",new BSONTimestamp(createdTimeMs,1));
            String realmConfigString = RealmConfigXMLProcessor.serialize(
                    (RealmConfiguration) tenant.getRealmConfig()).toString();
            InputStream is = new ByteArrayInputStream(realmConfigString.getBytes());
            prepStmt.setInt("UM_ACTIVE",is.available());
            prepStmt.insert();
        }catch(Exception ex){

            String msg = "Error in adding tenant with " + "tenant domain: " + tenant.getDomain().toLowerCase()
                    + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            prepStmt.close();
        }
        return id;
    }

    public void updateTenant(Tenant tenant) throws UserStoreException {

    }

    public Tenant getTenant(int i) throws UserStoreException {
        return null;
    }

    public Tenant[] getAllTenants() throws UserStoreException {
        return new Tenant[0];
    }

    public Tenant[] getAllTenantsForTenantDomainStr(String s) throws UserStoreException {
        return new Tenant[0];
    }

    public String getDomain(int i) throws UserStoreException {
        return null;
    }

    public int getTenantId(String s) throws UserStoreException {
        return 0;
    }

    public void activateTenant(int i) throws UserStoreException {

    }

    public void deactivateTenant(int i) throws UserStoreException {

    }

    public boolean isTenantActive(int i) throws UserStoreException {
        return false;
    }

    public void deleteTenant(int i) throws UserStoreException {

    }

    public void deleteTenant(int i, boolean b) throws UserStoreException {

    }

    public String getSuperTenantDomain() throws UserStoreException {
        return null;
    }

    private static int getCollectionSequence(String COLLECTION_NAME,DB db)
    {
        int seq=0;
        try {
            DBCollection collection = db.getCollection("COUNTERS");
            BasicDBObject dbObject =new BasicDBObject("_id",COLLECTION_NAME);
            DBCursor cursor = collection.find(dbObject);
            if(cursor.hasNext()){
                seq = Integer.parseInt(cursor.next().get("seq").toString());
                collection.update(new BasicDBObject("_id",COLLECTION_NAME),new BasicDBObject("$set",new BasicDBObject("seq",seq+1)));
            }
            else{
                collection.insert(new BasicDBObject("_id",COLLECTION_NAME).append("seq",1));
                seq=1;
            }
        }catch(MongoWriteException e){

            log.error("Error :"+e.getError().getMessage());
        }catch(MongoException e){

            log.error("Error :"+e.getMessage());
        }
        return seq;
    }
}
