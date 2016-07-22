package org.wso2.carbon.mongodb.db;

import com.mongodb.DB;
import org.json.JSONObject;

/**
 * Created by asantha on 5/15/16.
 */
public class MongoDBCreator {

    private DB dataSource;

    public MongoDBCreator(DB datasource){

        this.dataSource = datasource;
    }

    /*public boolean isDatabaseStructureCreated() {

        JSONObject object = new JSONObject(MongoDBDefaultRealmService.DB_CHECK_SQL);
        String collection = object.get("UM_USER").toString();
        return (dataSource.collectionExists(collection));
    }*/

    public void createRegistryDatabase() {

        dataSource.eval("");
    }
}
