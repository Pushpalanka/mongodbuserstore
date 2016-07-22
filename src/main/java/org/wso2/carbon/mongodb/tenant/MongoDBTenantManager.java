package org.wso2.carbon.mongodb.tenant;

import com.mongodb.*;
import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.bson.types.Binary;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.TenantManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.UserStoreDeploymentManager;
import org.wso2.carbon.user.core.config.RealmConfigXMLProcessor;
import org.wso2.carbon.user.core.tenant.TenantCache;
import org.wso2.carbon.user.core.tenant.TenantCacheEntry;
import org.wso2.carbon.user.core.tenant.TenantIdKey;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import java.util.Map;

/**
 * MongoDB Tenant Manager
 */
public class MongoDBTenantManager implements TenantManager {

    public DB dataSource;
    private static Log log = LogFactory.getLog(TenantManager.class);
    //protected BundleContext bundleContext;

    /**
     * Map which maps tenant domains to tenant IDs
     *
     * Key - tenant domain, value - tenantId
     */
    //private Map tenantDomainIdMap = new ConcurrentHashMap<String, Integer>();

    /**
     * This is the reverse of the tenantDomainIdMap. Key - tenantId, value - tenant domain
     */
    //private Map tenantIdDomainMap = new ConcurrentHashMap<Integer, String>();

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
            id = getCollectionSequence(dataSource);
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
            InputStream is = new ByteArrayInputStream(realmConfigString.getBytes("UTF-8"));
            byte b[] = new byte[is.available()];
            is.read(b);
            Binary binarStream = new Binary(b);
            prepStmt.setBinary("UM_USER_CONFIG",binarStream);
            prepStmt.setInt("UM_ACTIVE",1);
            prepStmt.insert();
        }catch(Exception ex){

            String msg = "Error in adding tenant with " + "tenant domain: " + tenant.getDomain().toLowerCase()
                    + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return id;
    }

    public void updateTenant(Tenant tenant) throws UserStoreException {

        tenantCacheManager.clearCacheEntry(new TenantIdKey(tenant.getId()));
        MongoPreparedStatement prepStmt = null;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.UPDATE_TENANT_MONGOQUERY);
            prepStmt.setString("UM_DOMAIN_NAME",tenant.getDomain().toLowerCase());
            prepStmt.setString("UM_EMAIL",tenant.getEmail());
            int createdTimeMs;
            Date createdTime = tenant.getCreatedDate();
            if (createdTime == null) {
                createdTimeMs = (int)System.currentTimeMillis();
            } else {
                createdTimeMs = (int)createdTime.getTime();
            }
            prepStmt.setTimeStamp("UM_CREATED_DATE", new BSONTimestamp(createdTimeMs,1));
            prepStmt.setInt("UM_ID", tenant.getId());
            prepStmt.update();
        }catch(Exception ex){
            String msg = "Error in updating tenant with " + "tenant domain: "
                    + tenant.getDomain().toLowerCase() + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
    }

    public Tenant getTenant(int tenantId) throws UserStoreException {

        @SuppressWarnings("unchecked")
        TenantCacheEntry<Tenant> entry = (TenantCacheEntry<Tenant>) tenantCacheManager
                .getValueFromCache(new TenantIdKey(tenantId));
        if ((entry != null) && (entry.getTenant() != null)) {
            return entry.getTenant();
        }
        MongoPreparedStatement prepStmt = null;
        Tenant tenant = null;
        int id;
        try {
            prepStmt = new MongoPreparedStatementImpl(dataSource, MongoTenantConstants.GET_TENANT_MONGOQUERY);
            prepStmt.setInt("UM_ID", tenantId);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()){

                id = Integer.parseInt(cursor.next().get("UM_ID").toString());
                String domain = cursor.next().get("UM_DOMAIN_NAME").toString();
                String email = cursor.next().get("UM_EMAIL").toString();
                BSONTimestamp timestamp = (BSONTimestamp) cursor.next().get("UM_CREATED_DATE");
                long time = timestamp.getTime();
                Date createdDate = getDate(time);
                int active = Integer.parseInt(cursor.next().get("UM_ACTIVE").toString());
                boolean status;
                status = active != 0;
                Binary binaryStream = (Binary)cursor.next().get("UM_USER_CONFIG");
                InputStream is = new ByteArrayInputStream(binaryStream.getData());
                RealmConfigXMLProcessor processor = new RealmConfigXMLProcessor();
                RealmConfiguration realmConfig = processor.buildRealmConfiguration(is);
                realmConfig.setTenantId(id);
                tenant = new Tenant();
                tenant.setId(id);
                tenant.setDomain(domain);
                tenant.setEmail(email);
                tenant.setCreatedDate(createdDate);
                tenant.setActive(status);
                tenant.setRealmConfig(realmConfig);
                setSecondaryUserStoreConfig(realmConfig, tenantId);
                tenant.setAdminName(realmConfig.getAdminUserName());
                tenantCacheManager.addToCache(new TenantIdKey(id), new TenantCacheEntry<Tenant>(tenant));
            }
        }catch (RuntimeException e){

            throw e;
        }catch(Exception ex){
            if(tenant!=null) {
                String msg = "Error in updating tenant with " + "tenant domain: "
                        + tenant.getDomain().toLowerCase() + ".";
                log.error(msg);
            }
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return tenant;
    }

    private Date getDate(long seconds){

        return new Date(seconds * 1000);
    }

    public Tenant[] getAllTenants() throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        List<Tenant> tenantList = new ArrayList<Tenant>();
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.GET_ALL_TENANTS_MONGOQUERY);
            DBCursor cursor = prepStmt.find();
            while(cursor.hasNext()){

                int id = Integer.parseInt(cursor.next().get("UM_ID").toString());
                String domain = cursor.next().get("UM_DOMAIN_NAME").toString();
                String email = cursor.next().get("UM_EMAIL").toString();
                BSONTimestamp timestamp = (BSONTimestamp) cursor.next().get("UM_CREATED_DATE");
                long time = timestamp.getTime();
                Date createdDate = getDate(time);
                int active = Integer.parseInt(cursor.next().get("UM_ACTIVE").toString());
                boolean status;
                status = active != 0;
                Binary binaryStream = (Binary)cursor.next().get("UM_USER_CONFIG");
                InputStream is = new ByteArrayInputStream(binaryStream.getData());
                RealmConfigXMLProcessor processor = new RealmConfigXMLProcessor();
                RealmConfiguration realmConfig = processor.buildRealmConfiguration(is);
                realmConfig.setTenantId(id);
                Tenant tenant = new Tenant();
                tenant.setId(id);
                tenant.setDomain(domain);
                tenant.setEmail(email);
                tenant.setCreatedDate(createdDate);
                tenant.setActive(status);
                tenant.setRealmConfig(realmConfig);
                tenant.setAdminName(realmConfig.getAdminUserName());
                tenantList.add(tenant);
            }
        }catch(Exception ex){

            String msg = "Error in getting the tenants.";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return tenantList.toArray(new Tenant[tenantList.size()]);
    }

    public Tenant[] getAllTenantsForTenantDomainStr(String domainSearch) throws UserStoreException {
        MongoPreparedStatement prepStmt = null;
        List<Tenant> tenantList = new ArrayList<Tenant>();
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.GET_MATCHING_TENANT_IDS_MONGOQUERY);
            prepStmt.setString("UM_DOMAIN_NAME",domainSearch);
            DBCursor cursor = prepStmt.find();
            while(cursor.hasNext()){

                int id = Integer.parseInt(cursor.next().get("UM_ID").toString());
                String domain = cursor.next().get("UM_DOMAIN_NAME").toString();
                String email = cursor.next().get("UM_EMAIL").toString();
                BSONTimestamp timestamp = (BSONTimestamp) cursor.next().get("UM_CREATED_DATE");
                long time = timestamp.getTime();
                Date createdDate = getDate(time);
                int active = Integer.parseInt(cursor.next().get("UM_ACTIVE").toString());
                boolean status;
                status = active != 0;
                Binary binaryStream = (Binary)cursor.next().get("UM_USER_CONFIG");
                InputStream is = new ByteArrayInputStream(binaryStream.getData());
                RealmConfigXMLProcessor processor = new RealmConfigXMLProcessor();
                RealmConfiguration realmConfig = processor.buildRealmConfiguration(is);
                realmConfig.setTenantId(id);
                Tenant tenant = new Tenant();
                tenant.setId(id);
                tenant.setDomain(domain);
                tenant.setEmail(email);
                tenant.setCreatedDate(createdDate);
                tenant.setActive(status);
                tenant.setRealmConfig(realmConfig);
                tenant.setAdminName(realmConfig.getAdminUserName());
                tenantList.add(tenant);
            }
        }catch(Exception ex){

            String msg = "Error in getting the tenants.";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return tenantList.toArray(new Tenant[tenantList.size()]);
    }

    public String getDomain(int tenantId) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        String domain = "";
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.GET_DOMAIN_MONGOQUERY);
            prepStmt.setInt("UM_ID",tenantId);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()){
                domain = cursor.next().get("UM_DOMAIN_NAME").toString();
            }
        }catch(Exception ex){

            String msg = "Error in getting the tenant with " + "tenant id: "
                    + tenantId + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return domain;
    }

    public int getTenantId(String domain) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        int tenantId = 0;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.GET_TENANT_ID_MONGOQUERY);
            prepStmt.setString("UM_DOMAIN_NAME",domain);
            DBCursor cursor = prepStmt.find();
            if(cursor.hasNext()){

                tenantId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            }
        }catch(Exception ex){
            String msg = "Error in getting the tenant with " + "tenant domain: "
                    + domain + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return tenantId;
    }

    public void activateTenant(int tenantId) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.ACTIVATE_MONGOQUERY);
            prepStmt.setInt("UM_ID",tenantId);
            prepStmt.setInt("UM_ACTIVE",1);
            prepStmt.update();
        }catch(Exception ex){
            String msg = "Error in activating the tenant with " + "tenant id: "
                    + tenantId + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
    }

    public void deactivateTenant(int tenantId) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.DEACTIVATE_MONGOQUERY);
            prepStmt.setInt("UM_ID",tenantId);
            prepStmt.setInt("UM_ACTIVE",0);
            prepStmt.update();
        }catch(Exception ex){
            String msg = "Error in activating the tenant with " + "tenant id: "
                    + tenantId + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
    }

    public boolean isTenantActive(int tenantId) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean active = false;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.IS_TENANT_ACTIVE_MONGOQUERY);
            prepStmt.setInt("UM_ID",tenantId);
            prepStmt.setInt("UM_ACTIVE",1);
            DBCursor cursor = prepStmt.find();
            active = cursor.hasNext();
        }catch(Exception ex){
            String msg = "Error in checking the tenant with " + "tenant id: "
                    + tenantId + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
        return active;
    }

    public void deleteTenant(int tenantId) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.DELETE_TENANT_MONGOQUERY);
            prepStmt.setInt("UM_ID",tenantId);
            prepStmt.remove();
        }catch(Exception ex){
            String msg = "Error in deleting the tenant with " + "tenant id: "
                    + tenantId + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
    }

    public void deleteTenant(int tenantId, boolean status) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        try{

            prepStmt = new MongoPreparedStatementImpl(dataSource,MongoTenantConstants.DELETE_TENANT_STATUS_MONGOQUERY);
            int id = 0;
            prepStmt.setInt("UM_ID",tenantId);
            if(status){
                id = 1;
            }
            prepStmt.setInt("UM_ACTIVE",id);
            prepStmt.remove();
        }catch(Exception ex){
            String msg = "Error in deleting the tenant with " + "tenant id: "
                    + tenantId + ".";
            log.error(msg);
            throw new UserStoreException(ex);
        }finally {
            if(prepStmt!=null) {
                prepStmt.close();
            }
        }
    }

    public String getSuperTenantDomain() throws UserStoreException {
        return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    }

    public String[] getAllTenantDomainStrOfUser(String username)
            throws org.wso2.carbon.user.api.UserStoreException {
        throw new UnsupportedOperationException("Operation getAllTenantDomainStrOfUse is unsupported " );
    }

    private static int getCollectionSequence(DB db)
    {
        int seq=0;
        try {
            DBCollection collection = db.getCollection("COUNTERS");
            BasicDBObject dbObject =new BasicDBObject("_id", "UM_TENANT");
            DBCursor cursor = collection.find(dbObject);
            if(cursor.hasNext()){
                seq = Integer.parseInt(cursor.next().get("seq").toString());
                collection.update(new BasicDBObject("_id", "UM_TENANT"),new BasicDBObject("$set",new BasicDBObject("seq",seq+1)));
            }
            else{
                collection.insert(new BasicDBObject("_id", "UM_TENANT").append("seq",1));
                seq=1;
            }
        }catch(MongoWriteException e){

            log.error("Error :"+e.getError().getMessage());
        }catch(MongoException e){

            log.error("Error :"+e.getMessage());
        }
        return seq;
    }

    private void setSecondaryUserStoreConfig(RealmConfiguration realmConfiguration, int tenantId)
            throws UserStoreException, IOException {

        RealmConfiguration lastRealm = realmConfiguration;
        if(realmConfiguration != null) {
            while(lastRealm.getSecondaryRealmConfig() != null) {
                lastRealm = lastRealm.getSecondaryRealmConfig();
            }

            String configPath = CarbonUtils.getCarbonTenantsDirPath() +
                    File.separator + tenantId + File.separator + "userstores";

            File userStores = new File(configPath);

            UserStoreDeploymentManager userStoreDeploymentManager = new UserStoreDeploymentManager();

            File[] files = userStores.listFiles(new FilenameFilter() {
                public boolean accept(File userStores, String name) {
                    return name.toLowerCase().endsWith(".xml");
                }
            });
            if (files != null) {
                for (File file : files) {
                    RealmConfiguration newRealmConfig = userStoreDeploymentManager.
                            getUserStoreConfiguration(file.getAbsolutePath());
                    if(newRealmConfig != null) {
                        lastRealm.setSecondaryRealmConfig(newRealmConfig);
                        lastRealm = lastRealm.getSecondaryRealmConfig();
                    }
                    else {
                        log.error("Error while creating realm configuration from file " + file.getAbsolutePath());
                    }
                }
            }
        }

    }
}
