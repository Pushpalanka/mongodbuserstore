package org.wso2.carbon.mongodb.query;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bson.types.BSONTimestamp;
import org.bson.types.Symbol;
import org.json.JSONObject;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBEncoder;
import com.mongodb.DBObject;
import com.mongodb.DBRef;
import com.mongodb.WriteConcern;
import com.mongodb.WriteResult;

public class MongoPreparedStatementImpl implements MongoPreparedStatement{

	private DB db=null;
	private DBCollection collection=null;
	private DBObject query=null;
	private DBObject projection;
	private String defaultQuery;
	private Map<String, Object> parameterValue;
	private JSONObject queryJson;
	private int parameterCount;
	
	public MongoPreparedStatementImpl(DB db,String query){
	
		if(this.db == null){
			this.db = db;
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



	public WriteResult update() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,this.projection);
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
				return this.collection.update(this.query,this.projection,upsert,multi);
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
				return this.collection.update(this.query,this.projection,upsert,multi,aWriteConcern);
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
				return this.collection.update(this.query,this.projection,upsert,multi,aWriteConcern,encoder);
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
				return this.collection.update(this.query,this.projection,upsert,multi,aWriteConcern,byPassDocumentValidation,encoder);
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
				return this.collection.updateMulti(this.query,this.projection);
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
		if(parameterValue.size()!= this.parameterCount){
			
			return false;
		}
		return true;
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
		
		Map<String,Object> mapQuery = new HashMap<String, Object>();
		Map<String,Object> mapProjection = new HashMap<String, Object>();
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
}
