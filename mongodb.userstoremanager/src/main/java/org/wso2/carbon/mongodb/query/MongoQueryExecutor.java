package org.wso2.carbon.mongodb.query;

import java.util.Map;

import org.wso2.carbon.user.core.UserStoreException;

import com.mongodb.DBObject;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBEncoder;
import com.mongodb.WriteConcern;
import com.mongodb.WriteResult;
import org.wso2.carbon.mongodb.query.MongoQueryException;

public class MongoQueryExecutor {
	
	private DB db=null;
	private DBCollection collection=null;
	Map<String, Object> map = null;
	
	public MongoQueryExecutor(DB database) throws UserStoreException{
		
		db = database;
	}
	
	public WriteResult insert(String collection,DBObject document,Object... params) throws MongoQueryException, UserStoreException{
		
		if(params != null)
		{
			if(!matchQueryWithParameters(document, params)){
			
				throw new MongoQueryException("parameters not matched with query");
			}
			else{
				document = getDBObject(document,params);
				return this.collection.insert(document);
			}
		}
		else{
			this.collection = db.getCollection(collection);
			return this.collection.insert(document);
		}
	}

	public DBCursor find(String collection) throws UserStoreException{
	
		this.collection = db.getCollection(collection);
		DBCursor cursor =  this.collection.find();
		return cursor;
	} 
	
	public DBCursor find(String collection,DBObject query,Object... params) throws UserStoreException, MongoQueryException{
		
		this.collection =db.getCollection(collection);
		if(params==null)
		{
			return this.collection.find(query);
		}
		else{
			if(!matchQueryWithParameters(query, params)){
				throw new MongoQueryException("parameters and objects are not matched");
			}
			else{
				query = getDBObject(query,params);
				return this.collection.find(query);
			}
		}
	}
	
	public DBCursor find(String collection,DBObject query,DBObject projection,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params==null){
			
			return this.collection.find(query, projection);
		}
		else{
			if(matchQueryWithParameters(query, params) && matchQueryWithParameters(projection, params)){
				query = getDBObject(query, params);
				projection = getDBObject(projection, params);
				return this.collection.find(query, projection);
			}
			else{
				throw new MongoQueryException("parameters and objects not matching");
			}
		}
	}
	
	public WriteResult update(String collection,DBObject document,DBObject condition,Object[] conditions,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params==null){
			
			return this.collection.update(condition,document);
		}else{
			if(matchUpdateQueryWithParameters(document,condition,conditions, params)){
				document = getDBObject(document, params);
				condition = getDBObject(condition, conditions);
				return this.collection.update(condition,new BasicDBObject("$set",document));
			}
			else{
				throw new MongoQueryException("Objects and parameter count not matched");
			}
		}
	}
	
	public WriteResult update(String collection,DBObject update,DBObject query,Object[] conditions,
			boolean upsert,boolean multi,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params == null){
			
			return this.collection.update(query, update,upsert,multi);
		}else{
			if(!matchUpdateQueryWithParameters(update, query,conditions,params)){
				
				throw new MongoQueryException("Parameters not matched with query");
			}
			else{
				update = getDBObject(update, params);
				query = getDBObject(query, conditions);
				return this.collection.update(query, new BasicDBObject("$set",update), upsert, multi);
			}
		}
	}
	
	public WriteResult update(String collection,DBObject update,DBObject query,Object[] conditions,
			boolean upsert,boolean multi,WriteConcern aWriteConcern,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params == null){
			
			return this.collection.update(query, update,upsert,multi,aWriteConcern);
		}else{
			if(!matchUpdateQueryWithParameters(update, query,conditions,params)){
				
				throw new MongoQueryException("Parameters not matched with query");
			}
			else{
				update = getDBObject(update, params);
				query = getDBObject(query, conditions);
				return this.collection.update(query, new BasicDBObject("$set",update), upsert, multi,aWriteConcern);
			}
		}
	}
	
	public WriteResult update(String collection,DBObject update,DBObject query,Object[] conditions,
			boolean upsert,boolean multi,WriteConcern aWriteConcern,DBEncoder encoder,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params == null){
			
			return this.collection.update(query, update,upsert,multi,aWriteConcern,encoder);
		}else{
			if(!matchUpdateQueryWithParameters(update, query,conditions,params)){
				
				throw new MongoQueryException("Parameters not matched with query");
			}
			else{
				update = getDBObject(update, params);
				query = getDBObject(query,conditions);
				return this.collection.update(query, new BasicDBObject("$set",update), upsert, multi,aWriteConcern,encoder);
			}
		}
	}
	
	public WriteResult update(String collection,DBObject update,DBObject query,Object[] conditions,
			boolean upsert,boolean multi,WriteConcern aWriteConcern,boolean bypassDocumentValidation,DBEncoder encoder,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params == null){
			
			return this.collection.update(query, update,upsert,multi,aWriteConcern,bypassDocumentValidation,encoder);
		}else{
			if(!matchUpdateQueryWithParameters(update, query,conditions,params)){
				
				throw new MongoQueryException("Parameters not matched with query");
			}
			else{
				update = getDBObject(update, params);
				query = getDBObject(query, conditions);
				return this.collection.update(query, new BasicDBObject("$set",update), upsert, multi,aWriteConcern,bypassDocumentValidation,encoder);
			}
		}
	}
	
	public WriteResult updateMulti(String collection,DBObject document,DBObject condition,Object[] conditions,Object... params) throws MongoQueryException{

		this.collection = db.getCollection(collection);
		if(params==null){

			return this.collection.updateMulti(condition,document);
		}else{
			if(matchUpdateQueryWithParameters(document,condition,conditions,params)){
				document = getDBObject(document, params);
				condition = getDBObject(condition, conditions);
				return this.collection.updateMulti(condition, new BasicDBObject("$set",document));
			}
			else{
				throw new MongoQueryException("Objects and parameter count not matched");
			}
		}
	}
	
	public WriteResult remove(String collection,DBObject query,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params == null){
			
			return this.collection.remove(query);
		}
		else{
			if(!matchQueryWithParameters(query, params)){
				
				throw new MongoQueryException("Parameters not matched with provided");
			}
			else{
				query = getDBObject(query, params);
				return this.collection.remove(query);
			}
		}
		
	}
	
	public WriteResult remove(String collection,DBObject query,WriteConcern concern,Object... params) throws MongoQueryException{
		
		this.collection = db.getCollection(collection);
		if(params == null){
			return this.collection.remove(query,concern);
		}
		else{
			if(!matchQueryWithParameters(query, params)){
				
				throw new MongoQueryException("query parameters not matched with provided");
			}
			else{
				query = getDBObject(query, params);
				return this.collection.remove(query,concern);
			}
		}
	}
	
	public WriteResult remove(String collection,DBObject query,WriteConcern concern,DBEncoder encoder,Object... params) throws MongoQueryException{

		this.collection = db.getCollection(collection);
		if(params == null){
			return this.collection.remove(query,concern,encoder);
		}
		else{
			if(!matchQueryWithParameters(query, params)){

				throw new MongoQueryException("query parameters not matched with provided");
			}
			else{
				query = getDBObject(query, params);
				return this.collection.remove(query,concern,encoder);
			}
		}
	}

	private boolean matchQueryWithParameters(DBObject document,Object... params){
		
		Map<String, Object> map = document.toMap();
		int paramsCount = 0;
		for(Map.Entry<String, Object> entry:map.entrySet()){
			
			String value = entry.getValue().toString();
			if(value.contains("?")){
				paramsCount++;
			}
		}
		int provideCount = params.length;
		if(provideCount != paramsCount)
		{
			return false;
		}
		return true;
	}

	private DBObject getDBObject(DBObject document,Object... params)
	{
		Map<String,Object> keyValue = document.toMap();
		int index=0;
		for(Map.Entry<String, Object> entry:keyValue.entrySet()){
			
			String value = entry.getValue().toString();
			if(value.contains("?")){
				entry.setValue(params[index]);
				index++;
			}
		}
		document = new BasicDBObject(keyValue);
		return document;
	}
	
	private DBObject getDBObject(DBObject document,Object[] conditions,Object... params)
	{
		Map<String,Object> keyValue = document.toMap();
		if(params != null){
			int index=0;
			for(Map.Entry<String, Object> entry:keyValue.entrySet()){

				String value = entry.getValue().toString();
				if(value.contains("?")){
					entry.setValue(params[index]);
					index++;
				}
			}
			document = new BasicDBObject(keyValue);
		}else{
			int index=0;
			for(Map.Entry<String, Object> entry:keyValue.entrySet()){

				String value = entry.getValue().toString();
				if(value.contains("?")){
					entry.setValue(conditions[index]);
					index++;
				}
			}
			document = new BasicDBObject(keyValue);
		}
		return document;
	}
	
	private boolean matchUpdateQueryWithParameters(DBObject document,DBObject query,Object[] conditions,Object... params){

		Map<String, Object> mapDocument = document.toMap();
		Map<String, Object> mapQuery = query.toMap();
		int paramsCount = 0;
		for(Map.Entry<String, Object> entry:mapDocument.entrySet()){

			String key = entry.getKey();
			String value = entry.getValue().toString();
			if(value.contains("?")){
				paramsCount++;
			}
		}
		for(Map.Entry<String, Object> entry:mapQuery.entrySet()){

			String key = entry.getKey();
			String value = entry.getValue().toString();
			if(value.contains("?")){
				paramsCount++;
			}
		}
		int provideCount = params.length+conditions.length;
		if(provideCount != paramsCount)
		{
			return false;
		}
		return true;
	}
}
