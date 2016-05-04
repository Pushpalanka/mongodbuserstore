package org.wso2.carbon.mongodb.query;

public class MongoQueryException extends Exception{

	private static final long serialVersionUID = 1997753363232807009L;

	public MongoQueryException(){
		
	}
	
	public MongoQueryException(String message){
		
		super(message);
	}
	
	public MongoQueryException(Throwable reason){
		
		super(reason);
	}
	
	public MongoQueryException(String message,Throwable reason){
		
		super(message,reason);
	}
	
	public MongoQueryException(String message, Throwable reason,
            boolean enableSuppression, boolean writableStackTrace){
		
		super(message,reason,enableSuppression,writableStackTrace);
	}
}
