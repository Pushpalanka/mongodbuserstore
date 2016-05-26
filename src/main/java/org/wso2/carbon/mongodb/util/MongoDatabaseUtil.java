package org.wso2.carbon.mongodb.util;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.mongodb.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.json.JSONObject;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.query.MongoQueryException;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBRealmConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.util.DatabaseUtil;

public class MongoDatabaseUtil {

	private static final Log log = LogFactory.getLog(DatabaseUtil.class);
    private static long connectionsCreated ;
    private static long connectionsClosed ;
    private static ExecutorService executor = null;

    private static DB dataSource = null;
    private static final int DEFAULT_MAX_ACTIVE = 40;
    private static final int DEFAULT_MAX_WAIT = 1000 * 60;
    private static final int DEFAULT_MIN_IDLE = 5;
    private static final int DEFAULT_MAX_IDLE = 6;
	private static final long DEFAULT_MIN_EVIC_TABLE_IDLE_TIME_MILLIS = 1000 * 60 * 30;
	private static final int DEFAULT_NUM_TESTS_PEREVICTION_RUN = 3;
	private static final int DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS = -1;
	private static final boolean DEFAULT_TEST_WHILE_IDLE = false;
	
	public static synchronized DB getRealmDataSource(RealmConfiguration realmConfiguration){
		
		if(dataSource == null){
			return createRealmDataSource(realmConfiguration);
		}
		else{
			return dataSource;
		}
	}

	public static DB createRealmDataSource(RealmConfiguration realmConfiguration) {
		// TODO Auto-generated method stub
		List<ServerAddress> seeds = new ArrayList<ServerAddress>();
		seeds.add(new ServerAddress(realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.URL)));
        char[] pass;
        if(realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PASSWORD)!=null) {
            pass = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PASSWORD).toCharArray();

        }else{
            pass = "admin123".toCharArray();
        }
        List<MongoCredential> credentials = new ArrayList<MongoCredential>();
        String userName;
        if(realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.USER_NAME)!= null){

            userName = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.USER_NAME);
        }else{
            userName = "admin";
        }
		credentials.add(
				MongoCredential.createCredential(userName,"wso2_carbon_db", pass)
		);
		MongoClient mongoClient = new MongoClient(seeds, credentials);
		mongoClient.setWriteConcern(WriteConcern.JOURNALED);
		dataSource = mongoClient.getDB("wso2_carbon_db");
		return dataSource;
	}
	
	public static int getIntegerValueFromDatabase(DB dbConnection,String stmt,Object... params) throws UserStoreException{
		
		MongoPreparedStatement prepStmt = null;
		int value = -1;
		JSONObject jsonKeys = new JSONObject(stmt);
		List<String> keys = getKeys(jsonKeys);
		try{
			if(params != null && params.length > 0){
				for(int i=0;i<params.length;i++){
					Object param = params[i];
					prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
					if(param==null){
						throw new UserStoreException("Null Data Provided");
					}else if(param instanceof String){
						prepStmt.setString(keys.get(i),(String)param);
					}else if(param instanceof Integer){
						prepStmt.setInt(keys.get(i), (Integer)param);
					}
				}
			}
			DBCursor cursor=prepStmt.find();
			while(cursor.hasNext()){
				value = Integer.parseInt(cursor.next().toString());
			}
			return value;
		}catch(NullPointerException ex){
			log.error(ex.getMessage(),ex);
            throw new UserStoreException(ex.getMessage(),ex);
		}catch(MongoQueryException ex){
			log.error(ex.getMessage(),ex);
			log.error("Using JSON Query :"+stmt);
			throw new UserStoreException(ex.getMessage(),ex);
		}finally {
			MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
		}
	}
	
	public static void updateUserRoleMappingInBatchMode(DB dbConnection,String stmt,Object... params) throws UserStoreException{
		
		MongoPreparedStatement prepStmt = null;
		boolean localConnection = false;
		JSONObject jsonKeys = new JSONObject(stmt);
		List<String> keys = getKeys(jsonKeys);
		try{
			prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
			int batchParamIndex = -1;
			if(params != null && params.length > 0){	
				for(int i=0;i<params.length;i++){
					
					Object param = params[i];
					if(param == null){
						throw new UserStoreException("Null data provided");
					}else if(param instanceof String[]){
						batchParamIndex = i;
					}else if(param instanceof String){
						prepStmt.setString(keys.get(i),(String)param);
					}else if(param instanceof Integer){
						prepStmt.setInt(keys.get(i),(Integer)param);
					}
				}
			}
			if(batchParamIndex != -1){
				String[] values = (String[])params[batchParamIndex];
				for(String value:values){
					prepStmt.setString(keys.get(batchParamIndex),value);
					prepStmt.insert();
				}
			}
            localConnection = true;
			if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Querry is : " + stmt + ": and result is"
                        + batchParamIndex);
            }
		}catch(MongoQueryException ex){
			
			log.error(ex.getMessage(), ex);
            log.error("Using json : " + stmt);
            throw new UserStoreException(ex.getMessage(), ex);
		}finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
	}
	
	public static void updateDatabase(DB dbConnection,String stmt,Map<String,Object> params) throws UserStoreException{
	
		MongoPreparedStatement prepStmt = null;
        WriteResult result = null;
		JSONObject jsonKeys = new JSONObject(stmt);
		List<String> keys = getKeys(jsonKeys);
		try{
			prepStmt = new MongoPreparedStatementImpl(dbConnection,stmt);
            Iterator<String> searchKeys = keys.iterator();
            while(searchKeys.hasNext()){
                String key = searchKeys.next();
                if(!key.equals("collection")||!key.equals("projection")||!key.equals("$set")) {
                    for(Map.Entry<String,Object> entry : params.entrySet()) {
                        if(entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                prepStmt.setString(key, null);
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            } else if (entry.getValue() instanceof Date) {
                                Date date = (Date) entry.getValue();
                                BSONTimestamp timestamp = new BSONTimestamp((int) date.getTime(), 1);
                                prepStmt.setTimeStamp(key, timestamp);
                            }
                        }
                    }
                }
            }
            int domainId = getIncrementedSequence(dbConnection,"UM_DOMAIN");
            prepStmt.setInt("UM_DOMAIN_ID",domainId);
            result = updateTrue(keys) ? prepStmt.update() : prepStmt.insert();
			if(log.isDebugEnabled()){
				log.debug("Executed querry is " + stmt + " and number of updated rows :: "+result.getN());
			}
		}catch(MongoQueryException ex){
			log.error("Error! "+ex.getMessage(),ex);
			log.error("Using json "+stmt);
			throw new UserStoreException("Error! "+ex.getMessage(),ex);
		}catch (Exception e){
            log.error("Error! "+e.getMessage(),e);
            throw new UserStoreException("Error! "+e.getMessage(),e);
        }finally{
			MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
		}
	}

    public static void deleteFromDatabase(DB dbConnection,String stmt,Map<String,Object> params) throws UserStoreException{

        MongoPreparedStatement prepStmt = null;
        WriteResult result = null;
        JSONObject jsonKeys = new JSONObject(stmt);
        List<String> keys = getKeys(jsonKeys);
        try{
            prepStmt = new MongoPreparedStatementImpl(dbConnection,stmt);
            Iterator<String> searchKeys = keys.iterator();
            while(searchKeys.hasNext()){
                if(!searchKeys.next().equals("collection")){
                    if (params.get(searchKeys.next()) == null) {
                        prepStmt.setString(searchKeys.next(), null);
                    } else if (params.get(searchKeys.next()) instanceof String) {
                        prepStmt.setString(searchKeys.next(), (String) params.get(searchKeys.next()));
                    } else if (params.get(searchKeys.next()) instanceof Integer) {
                        prepStmt.setInt(searchKeys.next(), (Integer) params.get(searchKeys.next()));
                    } else if (params.get(searchKeys.next()) instanceof Date) {
                        Date date = (Date) params.get(searchKeys.next());
                        BSONTimestamp timestamp = new BSONTimestamp((int) date.getTime(), 1);
                        prepStmt.setTimeStamp(searchKeys.next(), timestamp);
                    }
                }
            }
            result = prepStmt.remove();
            if(log.isDebugEnabled()){
                log.debug("Executed querry is " + stmt + " and number of deleted documents :: "+result.getN());
            }
        }catch(MongoQueryException ex){
            log.error("Error! "+ex.getMessage(),ex);
            log.error("Using json "+stmt);
            throw new UserStoreException("Error! "+ex.getMessage(),ex);
        }catch (Exception e){
            log.error("Error! "+e.getMessage(),e);
            throw new UserStoreException("Error! "+e.getMessage(),e);
        }finally{
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    private static boolean updateTrue(List<String> keys){

        for(String key : keys){

            if(key.equals("$set")){

                return true;
            }
        }
        return false;
    }
	
	private static List<String> getKeys(JSONObject stmt){
		
		int index = 0;
		List<String> keys=new ArrayList<String>();
		Iterator<String> keysfind = stmt.keys();
		while(keysfind.hasNext()){
			String key = keysfind.next();
            keys.add(index,key);
            if ( stmt.get(key) instanceof JSONObject ) {
                JSONObject value = stmt.getJSONObject(key);
                key = value.keys().next();
                keys.add(index,key);
            }
            index++;
		}
		return keys;	
	}
	
	public static void closeConnection(DB dbConnection) {     

        if (dbConnection != null) {
            try {
                dbConnection = null;
                incrementConnectionsClosed();
            } catch (MongoException e) {
                log.error("Database error. Could not close statement. Continuing with others. - " + e.getMessage(), e);
            }
        }
    }

    private static void closeStatement(MongoPreparedStatement preparedStatement) {

        if (preparedStatement != null) {
            try {
                preparedStatement.close();
            } catch (Exception e) {
                log.error("Database error. Could not close statement. Continuing with others. - " + e.getMessage(), e);
            }
        }

    }

    private static void closeStatements(MongoPreparedStatement... prepStmts) {

        if (prepStmts != null && prepStmts.length > 0) {
            for (MongoPreparedStatement stmt : prepStmts) {
                closeStatement(stmt);
            }
        }

    }

    public static void closeAllConnections(DB dbConnection, MongoPreparedStatement... prepStmts) {

        closeStatements(prepStmts);
        closeConnection(dbConnection);
    }

    public static long getConnectionsCreated() {
        return connectionsCreated;
    }

    public static long getConnectionsClosed() {
        return connectionsClosed;
    }

    public static synchronized void incrementConnectionsCreated() {
        if (connectionsCreated != Long.MAX_VALUE) {
            connectionsCreated++;
        }
    }

    public static synchronized void incrementConnectionsClosed() {
        if (connectionsClosed != Long.MAX_VALUE) {
            connectionsClosed++;
        }
    }

    public static void logDatabaseConnections() {
         executor = Executors.newCachedThreadPool();
         Runtime.getRuntime().addShutdownHook(new Thread(){
             public void run() {
                 executor.shutdownNow();
             }
         });
         final ScheduledExecutorService scheduler =
                 Executors.newScheduledThreadPool(10);
         Runtime.getRuntime().addShutdownHook(new Thread(){
             public void run() {
                 scheduler.shutdownNow();
             }
         });
         Runnable runnable = new Runnable() {
             public void run() {
                     log.debug("Total Number of Connections Created      : " +
                             getConnectionsCreated());
                     log.debug("Total Number of Connections Closed       : " +
                             getConnectionsClosed());
                 }
         };
         scheduler.scheduleAtFixedRate(runnable, 60, 60, TimeUnit.SECONDS);
     }

    public static void updateUserRoleMappingWithExactParams(DB dbConnection, String mongoQuery, String[] sharedRoles, String userName, Integer[] tenantIds, int currentTenantId) throws UserStoreException{

        MongoPreparedStatement ps = null;
        boolean localConnection = false;
        try {
            ps = new MongoPreparedStatementImpl(dbConnection,mongoQuery);
            JSONObject jsonKeys = new JSONObject(mongoQuery);
            List<String> keys = getKeys(jsonKeys);
            byte count = 0;
            byte index = 0;
            for (String role : sharedRoles) {
                count = 0;
                ps.setString(keys.get(++count), role);
                ps.setInt(keys.get(++count), tenantIds[index]);
                ps.setString(keys.get(++count), userName);
                ps.setInt(keys.get(++count), currentTenantId);
                ps.setInt(keys.get(++count), currentTenantId);
                ps.setInt(keys.get(++count), tenantIds[index]);

                if(updateTrue(keys))
                    ps.insert();
                else
                    ps.update();
                ++index;
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + mongoQuery);
            }
        } catch (Exception e) {
            String errorMessage = "Using sql : " + mongoQuery + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, ps);
        }
    }

	public static String[] getStringValuesFromDatabase(DB dbConnection, String mongoQuery,Object... params) throws UserStoreException{

        MongoPreparedStatement prepStmt = null;
        String[] values = new String[0];
        JSONObject jsonKeys = new JSONObject(mongoQuery);
        List<String> keys = getKeys(jsonKeys);
        try{
            if(params != null && params.length > 0){
                for(int i=0;i<params.length;i++){
                    Object param = params[i];
                    prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
                    if(param==null){
                        prepStmt.setString(keys.get(i+1),null);
                    }else if(param instanceof String){
                        prepStmt.setString(keys.get(i+1),(String)param);
                    }else if(param instanceof Integer){
                        prepStmt.setInt(keys.get(i+1), (Integer)param);
                    }
                }
            }
            DBCursor cursor=prepStmt.find();
            List<String> lst = new ArrayList<String>();
            while(cursor.hasNext()){
                lst.add(cursor.next().toString());
            }
            if (lst.size() > 0) {
                values = lst.toArray(new String[lst.size()]);
            }
            return values;
        }catch(NullPointerException ex){
            log.error(ex.getMessage(),ex);
            throw new UserStoreException(ex.getMessage(),ex);
        }catch(MongoQueryException ex){
            log.error(ex.getMessage(),ex);
            log.error("Using JSON Query :"+mongoQuery);
            throw new UserStoreException(ex.getMessage(),ex);
        }finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
	}

	public static void udpateUserRoleMappingInBatchModeForInternalRoles(DB dbConnection,String mongoStmt, String primaryDomain, Object... params) throws UserStoreException,MongoQueryException{

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            int batchParamIndex = -1;
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Null data provided.");
                    } else if (param instanceof String[]) {
                        batchParamIndex = i;
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i+1), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i+1), (Integer) param);
                    }
                }
            }
            int[] count = new int[batchParamIndex];
            if (batchParamIndex != -1) {
                String[] values = (String[]) params[batchParamIndex];
                int i=0;
                for (String value : values) {
                    String strParam = (String) value;
                    //add domain if not set
                    strParam = MongoUserCoreUtil.addDomainToName(strParam, primaryDomain);
                    //get domain from name
                    String domainParam = MongoUserCoreUtil.extractDomainFromName(strParam);
                    if (domainParam != null) {
                        domainParam = domainParam.toUpperCase();
                    }
                    //set domain to mongodb
                    prepStmt.setString(keys.get(params.length + 1), domainParam);
                    //remove domain before persisting
                    String nameWithoutDomain = MongoUserCoreUtil.removeDomainFromName(strParam);
                    //set name in mongodb
                    prepStmt.setString(keys.get(batchParamIndex + 1), nameWithoutDomain);
                    WriteResult result = prepStmt.update();
                    count[i] = result.getN();
                    i++;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + mongoStmt + ": and result is"
                        + Arrays.toString(count));
            }
        } catch (MongoQueryException e) {
            String errorMessage = "Using Mongo Query : " + mongoStmt + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeConnection(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
	}

    public static String[] getStringValuesFromDatabaseForInternalRoles(DB dbConnection,String mongoStmt, Object... params) throws MongoQueryException,UserStoreException{

        String[] values = new String[0];
        MongoPreparedStatement prepStmt = null;
        DBCursor cursor = null;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Null data provided.");
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i + 1), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i + 1), (Integer) param);
                    }
                }
            }
            cursor = prepStmt.find();
            List<String> lst = new ArrayList<String>();
            while (cursor.hasNext()) {
                String name = cursor.next().get(keys.get(1)).toString();
                String domain = cursor.next().get(keys.get(2)).toString();
                if (domain != null) {
                    name = MongoUserCoreUtil.addDomainToName(name, domain);
                }
                lst.add(name);
            }
            if (lst.size() > 0) {
                values = lst.toArray(new String[lst.size()]);
            }
            return values;
        } catch (MongoQueryException e) {
            String errorMessage = "Using mongo query : " + mongoStmt + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    public static void udpateUserRoleMappingInBatchMode(DB dbConnection,String mongoStmt, Object... params) throws UserStoreException{

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection,mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            int batchParamIndex = -1;
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Null data provided.");
                    } else if (param instanceof String[]) {
                        batchParamIndex = i;
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i + 1), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i + 1), (Integer) param);
                    }
                }
            }
            int count[] = new int[batchParamIndex];
            WriteResult result = null;
            if (batchParamIndex != -1) {
                String[] values = (String[]) params[batchParamIndex];
                int i=0;
                for (String value : values) {
                    prepStmt.setString(keys.get(batchParamIndex + 1), value);
                    result = prepStmt.update();
                    count[i] = result.getN();
                    i++;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + mongoStmt + ": and result is"
                        + Arrays.toString(count));
            }
        } catch (MongoQueryException e) {
            String errorMessage = "Using mongo query : " + mongoStmt + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    public static int getIncrementedSequence(DB dbConnection,String collection){

        DBObject checkObject = new BasicDBObject("name",collection);
        DBCollection collect = dbConnection.getCollection("COUNTERS");
        DBCursor cursor = collect.find(checkObject);
        int seq = 0;
        while (cursor.hasNext()){

            seq = Integer.parseInt(cursor.next().get("seq").toString());
        }
        collect.insert(new BasicDBObject("name",collection).append("seq",++seq));
        return seq;
    }
}
