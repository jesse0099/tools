const functions = require("firebase-functions");
const admin = require("firebase-admin");
const FieldValue = require('firebase-admin').firestore.FieldValue;

admin.initializeApp(functions.config().firebase);

// Clases (Excepciones)
class UnauthenticatedError extends Error {
  constructor(message) {
      super(message);
      this.message = message;
      this.type = 'UnauthenticatedError';
  }
}

class NotAnAdminError extends Error {
  constructor(message) {
      super(message);
      this.message = message;
      this.type = 'NotAnAdminError';
  }
}

class InvalidRoleError extends Error {
  constructor(message) {
      super(message);
      this.message = message;
      this.type = 'InvalidRoleError';
  }
}

// Funciones locales
// Roles permitidos
function roleIsValid(role) {
  const validRoles = ['admin', 'user', 'sa'];
  return validRoles.includes(role);
}

// Admin Creation
exports.createUser = functions.https.onCall(async (data, context) => {
  try {
      // Checking that the user calling the Cloud Function is authenticated
      if (!context.auth) {
        throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users can create new users.');
      }   
      // Checking that the user calling the Cloud Function is an Admin user
      const callerUid = context.auth.uid;  //uid of the user calling the Cloud Function
      const callerUserRecord = await admin.auth().getUser(callerUid);
      const caller_role = callerUserRecord.customClaims["https://hasura.io/jwt/claims"]["x-hasura-default-role"];
      
      var is_admin = false;
      if(caller_role === "admin" || caller_role === "sa")
        is_admin = true;

      if (!is_admin) {
        throw new NotAnAdminError('Only Admin users can create new users.');
      } 

      const json_data = JSON.parse(data);

      // Checking that the new user role is valid
      const role = json_data.role;
      if (!roleIsValid(role)) {
        throw new InvalidRoleError('The "' + role + '" role is not a valid role');
      }

      //FireStore request data
      const userCreationRequest = {
        userDetails: data,
        userEmail: json_data.email,
        status: 'Pending',
        createdBy: callerUid,
        createdOn: FieldValue.serverTimestamp()
      }

      const userCreationRequestRef = await admin.firestore().collection("userCreationRequests").add(userCreationRequest);

      const newUser = {
        email: json_data.email,
        emailVerified: false,
        password: json_data.password,
        displayName: json_data.firstName + ' ' + json_data.lastName,
        disabled: false
      }

      // Create user
      const userRecord = await admin
      .auth()
      .createUser(newUser);

      await userCreationRequestRef.update({ status: 'Treated' });

      return { result: 'The new user has been successfully created.' };

  } catch (error) {
    if (error.type === 'UnauthenticatedError') {
      throw new functions.https.HttpsError('unauthenticated', error.message);
    } else if (error.type === 'NotAnAdminError' || error.type === 'InvalidRoleError') {
      throw new functions.https.HttpsError('failed-precondition', error.message);
    } else {
      throw new functions.https.HttpsError('internal', error.message);
    }
  }
});

exports.adminCreationRequest = functions.https.onCall(async (data, context) => {
  try { 

    const json_data = JSON.parse(data);

    //FireStore request data
    const userCreationRequest = {
      userDetails: JSON.parse(data),
      userEmail: json_data.email,
      status: 'Pending',
      approvedBy: '',
      createdOn: FieldValue.serverTimestamp()
    }

    admin.firestore().collection("userCreationRequests").add(userCreationRequest);

  }catch(error){
    throw new functions.https.HttpsError('Internal', error.message);
  } 
});

// On sign up.
exports.processSignUp = functions.auth.user().onCreate((user, context) => {
      var customClaims = {};
      var role;
      var admin_creation_collection = admin.firestore().collection("userCreationRequests");
      // Create a query against the collection.
      var admin_creation_query = admin_creation_collection.where("userEmail", "==", user.email).get();

      return admin_creation_query.then((query_snapshot) => {
        if(query_snapshot.empty){
          role = "user";
          customClaims = {
            "https://hasura.io/jwt/claims": {
              "x-hasura-default-role": "user",
              "x-hasura-allowed-roles": ["user"],
              "x-hasura-user-id": user.uid,
            },
          };
        }else{
          role = "admin";
          customClaims = {
            "https://hasura.io/jwt/claims": {
              "x-hasura-default-role": "admin",
              "x-hasura-allowed-roles": ["admin"],
              "x-hasura-user-id": user.uid,
            },
          };
        }
      }).then(()=>{

        return admin
        .auth()
        .setCustomUserClaims(user.uid, customClaims)
        .then(() => {
          // Update real-time database to notify client to force refresh.
          const metadataRef = admin.database().ref("metadata/" + user.uid);
          return metadataRef.set({refreshTime: new Date().getTime(),
            email: user.email,
            def_role: role
          });
        })
        .catch((error) => {
          throw new functions.https.HttpsError('internal', error.message);
        });
      });
});
