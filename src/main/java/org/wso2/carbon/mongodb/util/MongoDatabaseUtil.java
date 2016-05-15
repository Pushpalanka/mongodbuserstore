package org.wso2.carbon.mongodb.util;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.json.JSONObject;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.query.MongoQueryException;
import org.wso2.carbon.mongodb.userstoremanager.MongoDBRealmConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.DatabaseUtil;

import com.mongodb.DB;
import com.mongodb.DBCursor;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.MongoException;
import com.mongodb.ServerAddress;
import com.mongodb.WriteConcern;
import com.mongodb.WriteResult;

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
	
	public static synchronized DB getRealmDataSource(){
		
		if(dataSource == null){
			return createRealmDataSource();
		}
		else{
			return dataSource;
		}
	}

	public static DB createRealmDataSource() {
		// TODO Auto-generated method stub
		List<ServerAddress> seeds = new ArrayList<ServerAddress>();
		seeds.add(new ServerAddress(MongoDBRealmConstants.URL));
		char[] pass=MongoDBRealmConstants.PASSWORD.toCharArray();
		List<MongoCredential> credentials = new ArrayList<MongoCredential>();
		credentials.add(
				MongoCredential.createCredential(MongoDBRealmConstants.USER_NAME,"wso2_carbon_db", pass)
		);
		MongoClient mongoClient = new MongoClient(seeds, credentials);
		mongoClient.setWriteConcern(WriteConcern.JOURNALED);
		dataSource = (DB)mongoClient.getDatabase("wso2_carbon_db");		
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
	
	public static void updateDatabase(DB dbConnection,String stmt,Object... params) throws UserStoreException{
	
		MongoPreparedStatement prepStmt = null;
		JSONObject jsonKeys = new JSONObject(stmt);
		List<String> keys = getKeys(jsonKeys);
		try{
			prepStmt = new MongoPreparedStatementImpl(dbConnection,stmt);
			if(params != null && params.length > 0){
				for(int i=0;i < params.length; i++){
					Object param = params[i];
					if(param==null){
						throw new UserStoreException("Null data provided");
					}else if(param instanceof String){
						prepStmt.setString(keys.get(i), (String)param);
					}else if(param instanceof Integer){
						prepStmt.setInt(keys.get(i), (Integer)param);
					}else if(param instanceof Date){
						Date date = (Date)param;
						BSONTimestamp timestamp = new BSONTimestamp((int)date.getTime(),1);
						prepStmt.setTimeStamp(keys.get(i),timestamp);
					}
				}
			}
			WriteResult result=prepStmt.update();
			if(log.isDebugEnabled()){
				log.debug("Executed querry is " + stmt + " and number of updated rows :: "+result.getN());
			}
		}catch(MongoQueryException ex){
			log.error("Error! "+ex.getMessage(),ex);
			log.error("Using json "+stmt);
			throw new UserStoreException("Error! "+ex.getMessage(),ex);
		}finally{
			MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
		}
	}
	
	private static List<String> getKeys(JSONObject stmt){
		
		int index = 0;
		List<String> keys=new ArrayList<String>();
		Iterator<String> keysfind = stmt.keys();
		while(keysfind.hasNext()){
			String key = keysfind.next();
	        try{
	             JSONObject value = stmt.getJSONObject(key);
	             getKeys(value);
	        }catch(Exception e){
	        	if(stmt.get(key).equals("?")){
	        		index++;
	        		keys.add(index,stmt.get(key).toString());
	        	}
	        }
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
}
