package org.wso2.carbon.mongodb.dao;

import com.mongodb.DB;
import com.mongodb.DBCursor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.query.MongoQueryException;
import org.wso2.carbon.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.user.core.UserStoreException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Created by asantha on 5/16/16.
 */
public class MongoDBUserStoreConfigDao {

    private Log log = LogFactory.getLog(MongoDBUserStoreConfigDao.class);
    private DB dataSource;

    public MongoDBUserStoreConfigDao(DB dataSource){

        this.dataSource = dataSource;
        MongoDatabaseUtil.logDatabaseConnections();
    }

    public Map<String,String>  getCustomUserStoreConfiguration(int tenantId) throws UserStoreException{

        MongoPreparedStatement prepStmt;
        Map<String,String> props = new HashMap<String, String>();
        try{
            String query = "{'collection' : 'UM_CUSTOM_USERSTORE','UM_TENANT_ID' : '?','projection' : '{'UM_USERSTORE_PROPERTY' : '1','UM_USERSTORE_VALUE' : '1'}'}";
            prepStmt = new MongoPreparedStatementImpl(this.dataSource,query);
            prepStmt.setInt("UM_TENANT_ID",tenantId);
            DBCursor cursor = prepStmt.find();
            while(cursor.hasNext()){

                String property = cursor.next().get("UM_USERSTORE_PROPERTY").toString();
                String value = cursor.next().get("UM_USERSTORE_VALUE").toString();
                props.put(property,value);
            }
            prepStmt.close();
        }catch(MongoQueryException ex){

            log.error("Cannot Retrieve User Store Properties "+ex);
            throw new UserStoreException(ex);
        }
        return props;
    }

    public void addCustomUserStoreConfiguration(Map<String,String> props,int tenantId) throws UserStoreException{

        MongoPreparedStatement prepStmt=null;
        try{
            String query = "{'collection' : 'UM_CUSTOM_USERSTORE','UM_USERSTORE_PROPERTY' : '?','UM_USERSTORE_VALUE' : '?',UM_TENANT_ID : '?'}";
            prepStmt = new MongoPreparedStatementImpl(this.dataSource,query);
            for (Iterator<Map.Entry<String, String>> ite = props.entrySet().iterator(); ite.hasNext();) {

                Map.Entry<String, String> entry = ite.next();
                prepStmt.setString("UM_USERSTORE_PROPERTY",entry.getKey());
                prepStmt.setString("UM_USERSTORE_VALUE",entry.getValue());
                prepStmt.setInt("UM_TENANT_ID",tenantId);
                prepStmt.insert();
            }
        }catch(MongoQueryException ex){

            log.error("Cannot add user store properties "+ex);
            throw new UserStoreException(ex);
        }finally {
            prepStmt.close();
        }

    }
}
