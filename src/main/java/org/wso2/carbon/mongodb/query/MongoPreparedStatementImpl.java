package org.wso2.carbon.mongodb.query;

import java.util.*;

import com.mongodb.*;
import org.bson.types.BSONTimestamp;
import org.bson.types.Binary;
import org.bson.types.Symbol;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.user.api.UserStoreException;

public class MongoPreparedStatementImpl implements MongoPreparedStatement{

	private DB db=null;
	private DBCollection collection=null;
	private DBObject query=null;
	private DBObject projection;
	private String defaultQuery;
	private Map<String, Object> parameterValue;
	private JSONObject queryJson;
	private int parameterCount;
	private Map<String,Object> mapQuery = null;
	private Map<String,Object> mapProjection = null;
	private Map<String,Object> mapMatch = null;
	private Map<String,Object> mapProject = null;
	private Map<String,Object> mapSort = null;
	private Map<String,Object> mapLookUp = null;
	private Map<String,Object> mapGroup = null;
	private Map<String,Object> mapUnwind = null;
	
	public MongoPreparedStatementImpl(DB db,String query){
	
		if(this.db == null){
			this.db = db;
		}
		if(mapQuery == null && mapProjection == null){

			mapQuery = new HashMap<String, Object>();
			mapProjection = new HashMap<String, Object>();
		}
		if(mapMatch == null){
			mapMatch = new HashMap<String, Object>();
		}
		this.defaultQuery = query;
		this.queryJson = new JSONObject(defaultQuery);
		parameterValue = new HashMap<String, Object>();
		this.projection = null;
		this.parameterCount = 0;
	}
	
	

	public void close() {
		
		this.db = null;
		this.collection = null;
		this.query = null;
		this.projection = null;
		this.parameterValue =null;
		this.defaultQuery = null;
		this.queryJson = null;
		this.parameterCount = 0;
		this.mapQuery = null;
		this.mapProjection = null;
		this.mapMatch = null;
		this.mapLookUp = null;
		this.mapProject =null;
		this.mapSort = null;
		this.mapGroup = null;
		this.mapUnwind = null;
	}



	public void setInt(String key, int parameter){
	
		parameterValue.put(key,parameter);
	}



	public void setDouble(String key, double parameter){

		parameterValue.put(key,parameter);
	}



	public void setString(String key, String parameter){
	
		parameterValue.put(key, parameter);
	}



	public void setTimeStamp(String key, BSONTimestamp timeStamp){
		
		parameterValue.put(key, timeStamp);
	}



	public void setObject(String key, Object object) {
		
		parameterValue.put(key, object);
	}



	public void setDate(String key, Date date){
		
		parameterValue.put(key, date);
	}



	public void setBoolean(String key, boolean parameter){
		
		parameterValue.put(key, parameter);
	}



	public void setDBPointer(String key, DBRef dbRef){
		
		parameterValue.put(key, dbRef);
	}



	public void setSymbol(String key, Symbol symbol){
		
		parameterValue.put(key, symbol);
	}



	public void setRegularExpression(String key, String parameter){
		
		parameterValue.put(key, parameter);
	}

	public void setLong(String key, long parameter){
		
		parameterValue.put(key, parameter);
	}

	public void setBinary(String key, Binary stream) {

		parameterValue.put(key,stream);
	}

	public void setArray(String key,ArrayList<Object> parameters){
	
		parameterValue.put(key,parameters);
	}

	public WriteResult insert() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.insert(this.query);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public DBCursor find() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				if(this.projection==null && this.query==null){
					return this.collection.find();
				}else if(this.projection==null){
					return this.collection.find(this.query);
				}else{
					return this.collection.find(this.query,this.projection);
				}
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}

    public AggregationOutput aggregate() throws UserStoreException{

        JSONObject defaultObject = new JSONObject(defaultQuery);
        getAggregrationObjects(defaultObject);
        try{

            DBObject match = new BasicDBObject("$match",new BasicDBObject(mapMatch));
            DBObject lookup = new BasicDBObject("$lookup",new BasicDBObject(mapLookUp));
            DBObject project = new BasicDBObject("$project",new BasicDBObject(mapProject));
            List<DBObject> pipeline = new ArrayList<DBObject>();
            pipeline.add(match);
            pipeline.add(lookup);
            pipeline.add(project);
            if(mapSort != null){

                DBObject sort = new BasicDBObject("$sort",new BasicDBObject(mapSort));
                pipeline.add(sort);
            }
            if(mapGroup != null){

                DBObject group = new BasicDBObject("$group",new BasicDBObject(mapGroup));
                pipeline.add(group);
            }
            if(mapUnwind != null){

                DBObject unwind = new BasicDBObject("$unwind",new BasicDBObject(mapUnwind));
                pipeline.add(unwind);
            }
            return this.collection.aggregate(pipeline);
        }catch(MongoException e){

            throw new UserStoreException(e.getMessage());
        }
    }

	public WriteResult update() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection));
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi) throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern) throws MongoQueryException {
		
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi,aWriteConcern);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern, DBEncoder encoder)
			throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi,aWriteConcern,encoder);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern,
			boolean byPassDocumentValidation,DBEncoder encoder) throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi,aWriteConcern,byPassDocumentValidation,encoder);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult updateMulti() throws MongoQueryException {
		
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.updateMulti(this.query,new BasicDBObject("$set",this.projection));
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult remove() throws MongoQueryException{
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.remove(this.query);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}
	
	public WriteResult remove(WriteConcern concern) throws MongoQueryException{
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.remove(this.query,concern);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}
	
	public WriteResult remove(WriteConcern concern,DBEncoder encoder) throws MongoQueryException{
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.remove(this.query,concern,encoder);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}
	private boolean matchArguments(JSONObject query){
		
		Iterator<String> keys = query.keys();
		while(keys.hasNext()){
			String key = keys.next();
	        try{
	             JSONObject value = query.getJSONObject(key);
	             matchArguments(value);
	        }catch(Exception e){
	        	if(query.get(key).equals("?")){
	        		this.parameterCount++;
	        	}
	        }
		}
		return parameterValue.size() == this.parameterCount;
	}

	private boolean convertToDBObject(String query){
		
		JSONObject queryObject = new JSONObject(query);
		if(queryObject.has("collection")){
			String collection = queryObject.getString("collection");
			this.collection = this.db.getCollection(collection);
			queryObject.remove("collection");
			setQueryObject(queryObject,false);
			return true;
		}
		else{
			return false;
		}
	}
	
	private void setQueryObject(JSONObject object,boolean status){

        boolean hasProjection = status;
        Iterator<String> keys = object.keys();
        while(keys.hasNext()){
            String key = keys.next();
            Object val=null;
            try{
                JSONObject value = object.getJSONObject(key);
                if(key.equals("projection")){
                    hasProjection = true;
                }
                setQueryObject(value,hasProjection);
            }catch(Exception e){
                if(parameterValue.containsKey(key)){
                    val = parameterValue.get(key);
                }
            }
            if(val != null){
                if(!hasProjection){
                    mapQuery.put(key,val);
                }else{
                    mapProjection.put(key, val);
                }
            }
        }
        this.query = new BasicDBObject(mapQuery);
        if(!mapProjection.isEmpty()){
            this.projection = new BasicDBObject(mapProjection);
        }
	}

    private void getAggregrationObjects(JSONObject stmt){

        Iterator<String> keys = stmt.keys();
        while(keys.hasNext()){

            String key = keys.next();
            JSONObject value=null;
            try{
                if(!key.equals("collection"))
                {
                    value = stmt.getJSONObject(key);
                }
            }catch(JSONException e){

                throw new JSONException(e.getMessage());
            }
            if(key.equals("collection")){

                this.collection = db.getCollection(key);
            }else if(key.equals("$lookup")){

                mapLookUp = toMap(value);
            }else if(key.equals("$project")){

                mapProject = toMap(value);
            }else if(key.equals("$sort")){

                mapSort = toMap(value);
            }else if(key.equals("$group")){

                mapGroup = toMap(value);
            }else if(key.equals("$unwind")){

                mapUnwind =toMap(value);
            }else{

                setMatchObject(value);
            }
        }
    }

    public void setMatchObject(JSONObject stmt){

        Iterator<String> keys = stmt.keys();
        while(keys.hasNext()){
            String key = keys.next();
            if(parameterValue.containsKey(key)){
                Object val= parameterValue.get(key);
                mapMatch.put(key, val);
            }
        }
    }
    public static Map<String, Object> toMap(JSONObject object) throws JSONException {
        Map<String, Object> map = new HashMap<String, Object>();

        Iterator<String> keysItr = object.keys();
        while(keysItr.hasNext()) {
            String key = keysItr.next();
            Object value = object.get(key);

            if(value instanceof JSONArray) {
                value = toList((JSONArray) value);
            }

            else if(value instanceof JSONObject) {
                value = toMap((JSONObject) value);
            }
            map.put(key, value);
        }
        return map;
    }

    public static List<Object> toList(JSONArray array) throws JSONException {
        List<Object> list = new ArrayList<Object>();
        for(int i = 0; i < array.length(); i++) {
            Object value = array.get(i);
            if(value instanceof JSONArray) {
                value = toList((JSONArray) value);
            }

            else if(value instanceof JSONObject) {
                value = toMap((JSONObject) value);
            }
            list.add(value);
        }
        return list;
    }
}
