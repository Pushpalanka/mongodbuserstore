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

here this getNextSequence is to auto_increment id in UM_DOMAIN collection since MongoDB doesn't have auto_increment i implement it using a simple script and COUNTERS is for store the current sequence of collection

after that go to add user store in IS admin console and select MongoDBUserStoreManager from UserStoreManager class dropdown 
then create a new user store with giving appropriate connection configuration

and thats all it will create a new mongodb userstore in Identity Server
