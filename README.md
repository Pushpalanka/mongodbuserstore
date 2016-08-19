# mongodbuserstore

First create a Database in MongoDB named wso2_carbon_db 
In mongodb if you create a empty database without a collections it will store it in RAM and not store permanelty therefore create a samle collection using below script

    db.system.js.save(
    {

     _id: "getNextSequence",

     value : function(name) { 

            

        var ret = db.COUNTERS.findAndModify(

          {

            query: { _id: name },

            update: { $inc: { seq: 1 } },

            new: true

          }

        );



        return ret.seq;

     }

    }

    );
    db.COUNTERS.insert({

     _id: "UM_DOMAIN",

      seq: 0

    });
    db.UM_DOMAIN.insert({
      UM_DOMAIN_ID: getNextSequence("UM_DOMAIN"),
      UM_DOMAIN_NAME: "",
      UM_TENANT_ID: 0
    });

here this getNextSequence is to auto_increment id in UM_DOMAIN collection since MongoDB doesn't have auto_increment i implemented it using a simple script and COUNTERS is for store the current sequence of collection

to deploy MongoDBUserStoreManager to WSO2 Identity Server you need to add mongo-java-driver jar to deployment folder in IS you can download it from <a href="http://central.maven.org/maven2/org/mongodb/mongo-java-driver/3.2.2/">here</a> just download the mongo-java-driver-3.2.2.jar from there
after that you can deploy the identity server by running wso2server.sh in linux or wso2server.bat in windows 

Finally go to add user store in IS admin console and select MongoDBUserStoreManager from UserStoreManager class dropdown 
then create a new user store with giving appropriate connection configuration

and thats all it will create a new mongodb userstore in Identity Server there after you can do user related activities in IS inside mongodb user store domain since this is development repository you can simply download this and install it using <b>mvn clean install</b>  
after successfully built get the jar from target folder and add it with mongo-java-driver you download from above link and get the json lib also from here and add to deployment folder

If you want IS to default have the MongoDBUserStore you can simply clone product-is repository from <a href="https://github.com/asanthamax/product-is">here</a> and identity-mongodb-extension from <a href="https://github.com/asanthamax/identity-userstore-mongodb">here</a> and first build the mongodb-extension using maven clean install command and after successfully built it build product-is using  <b>mvn clean install -Dmaven.test.skip=true</b> command there after it will build a wso-IS zip you can find it inside modules/distributions/target folder get it and unzip and add mongo-java-driver to dropins folder and run the server,you should be able to see MongoDBUserStoreManager in dropdown in create user store UI in admin console
this is still not merged to wso2 identity server main repo and mongodb user store manin extension where it will be more likely distributed with IS 5.3.0 until that you can follow one of the process describe in above to deploy mongodbuser store in wso2 identity server 

All the documents related to this userstore you can find my repository and below i shared publicaly with google doc also

[1] https://docs.google.com/document/d/1mdnmYruzQz5QSxAYwM1XVeJntJMFdxUsV5gord7LuPA/edit?usp=sharing
[2] https://docs.google.com/document/d/1fCLfZYsPOBkHMzRCGM3aexoBSplX3bKIRmONmFsgkBc/edit?usp=sharing
[3] http://googledrive.com/host/0B__ZE1ru1jkXbDVoSDlveV9yNk0
[4] https://docs.google.com/spreadsheets/d/1jwSR_qFV-LfOS7ZTZ8CpiFFTYPoudDQF7zQhvblivaE/edit?usp=sharing

And below has the link to my blog which contain all my gsoc2016 experience

http://asanthamax.blogspot.com
