package org.wso2.carbon.mongodb.query;

import java.util.ArrayList;
import java.util.Date;
import org.bson.types.BSONTimestamp;
import org.bson.types.Symbol;

import com.mongodb.DBCursor;
import com.mongodb.DBEncoder;
import com.mongodb.DBRef;
import com.mongodb.WriteConcern;
import com.mongodb.WriteResult;

public interface MongoPreparedStatement {

	public void setInt(String key,int parameter);
	
	public void setDouble(String key,double parameter);
	
	public void setString(String key,String parameter);
	
	public void setTimeStamp(String key,BSONTimestamp timeStamp);
	
	public void setArray(String key,ArrayList<Object> parameters);
	
	public void setObject(String key,Object object);
	
	public void setDate(String key,Date date);
	
	public void setBoolean(String key,boolean parameter);
	
	public void setDBPointer(String key,DBRef dbRef);
	
	public void setSymbol(String key,Symbol symbol);
	
	public void setRegularExpression(String key,String parameter);
	
	public void setLong(String key,long parameter);
	
	public void close();
	
	public WriteResult insert() throws MongoQueryException;
	
	public DBCursor find() throws MongoQueryException;
	
	public WriteResult update() throws MongoQueryException;
	
	public WriteResult update(boolean upsert,boolean multi) throws MongoQueryException;
	
	public WriteResult update(boolean upsert,boolean multi,WriteConcern aWriteConcern) throws MongoQueryException;
	
	public WriteResult update(boolean upsert,boolean multi,WriteConcern aWriteConcern,DBEncoder encoder) throws MongoQueryException;
	
	public WriteResult update(boolean upsert,boolean multi,WriteConcern aWriteConcern,boolean byPassDocumentValidation,DBEncoder encoder) throws MongoQueryException;
	
	public WriteResult updateMulti() throws MongoQueryException;
	
	public WriteResult remove() throws MongoQueryException;
	
	public WriteResult remove(WriteConcern concern) throws MongoQueryException;
	
	public WriteResult remove(WriteConcern concern,DBEncoder encoder) throws MongoQueryException;
}
