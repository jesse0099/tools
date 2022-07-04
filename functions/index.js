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

//Already treated account
class AlreadyTreatedAccount extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.type = 'AlreadyTreatedAccount';
  }
}

// Funciones locales
// Roles permitidos
function roleIsValid(role) {
  const validRoles = ['admin', 'user', 'sa'];
  return validRoles.includes(role);
}


//Get Admin Creation Requests
exports.adminCreationRequests = functions.https.onCall(async (data, context) => {
  try {
    // Checking that the user calling the Cloud Function is authenticated
    if (!context.auth) {
      throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users can call this function.');
    }
    // Checking that the user calling the Cloud Function is an Admin user
    const callerUid = context.auth.uid;  //uid of the user calling the Cloud Function
    const callerUserRecord = await admin.auth().getUser(callerUid);
    const caller_role = callerUserRecord.customClaims["https://hasura.io/jwt/claims"]["x-hasura-default-role"];

    var is_admin = false;
    if (caller_role === "admin" || caller_role === "sa")
      is_admin = true;

    if (!is_admin) {
      throw new NotAnAdminError('Only Admin users can read requests.');
    }

    var admin_creation_collection = admin.firestore().collection("userCreationRequests");

    var snapshot = await admin_creation_collection.get();

    return snapshot.docs;

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

// Admin Creation Approval
exports.adminCreationApproval = functions.https.onCall(async (data, context) => {
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
    if (caller_role === "admin" || caller_role === "sa")
      is_admin = true;

    if (!is_admin) {
      throw new NotAnAdminError('Only Admin users can create new users.');
    }

    const json_data = JSON.parse(data);

    // Checking that the new user role is valid
    const role = json_data._adminAccountDetail.Role;
    if (!roleIsValid(role)) {
      throw new InvalidRoleError('The "' + role + '" role is not a valid role');
    }
    const newUser = {
      email: json_data._adminAccountDetail.Email,
      emailVerified: false,
      password: json_data._adminAccountDetail.Password,
      displayName: json_data._adminAccountDetail.FirstName + ' ' + json_data._adminAccountDetail.LastName,
      disabled: false
    };

    const userCreationRequestRef = admin.firestore()
      .collection("userCreationRequests").doc(json_data._docId);

    userCreationRequestRef.update({ status: 'Processing'}).then((data)=>{
      admin.auth().createUser(newUser).then((user_record)=>{
          const new_user_id = user_record.uid;
          const customClaims = {
            "https://hasura.io/jwt/claims": {
              "x-hasura-default-role": "admin",
              "x-hasura-allowed-roles": ["admin"],
              "x-hasura-user-id": new_user_id,
            },
          };
          (async () => await admin.auth().setCustomUserClaims(new_user_id, customClaims))().then(()=>{
            userCreationRequestRef.update({ status: 'Treated', approvedBy: callerUid});
            return {message: "Admin created"};
          });
      });
    });

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

// Admin Creation Request
exports.adminCreationRequest = functions.https.onCall(async (data, context) => {
  try {
    var existent_account = false;
    const json_data = JSON.parse(data);
    const collection_reference = await admin.firestore().collection("userCreationRequests");
    const query = collection_reference.where("userEmail", "==", json_data.email)
      .where("status", "in", ['Pending', 'Treated']).get();

    await query.then((snapshot) => {
      if (!snapshot.empty)
        existent_account = true;
    });

    if (existent_account)
      throw new AlreadyTreatedAccount("Account already in use");

    //FireStore request data
    const userCreationRequest = {
      docId: '',
      userDetails: JSON.parse(data),
      userEmail: json_data.email,
      status: 'Pending',
      approvedBy: '',
      createdOn: FieldValue.serverTimestamp(),
      motive: '',
    };

    const creation_reference = await admin.firestore().collection("userCreationRequests").add(userCreationRequest);

    await creation_reference.update({ docId: creation_reference.id });

  } catch (error) {
    if (error.type === "AlreadyTreatedAccount") {
      throw new functions.https.HttpsError('already_exists', error.message);
    } else {
      throw new functions.https.HttpsError('internal', error.message);
    }
  }
});

// On sign up.
exports.processSignUp = functions.auth.user().onCreate(async (user, context) => {
  var customClaims = {};
  var role;
  var admin_creation_collection = admin.firestore().collection("userCreationRequests");
  // Create a query against the collection.
  //Consultar estado "Pendiente"
  var admin_creation_query = await admin_creation_collection.where("userEmail", "==", user.email)
  .where("status", "==", "Processing").get();
  
  if (admin_creation_query.empty) {
    role = "user";
    customClaims = {
      "https://hasura.io/jwt/claims": {
        "x-hasura-default-role": "user",
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-user-id": user.uid,
      },
    };
    try {
      await admin
        .auth()
        .setCustomUserClaims(user.uid, customClaims);
      // Update real-time database to notify client to force refresh.
      const metadataRef = admin.database().ref("metadata/" + user.uid);
      return await metadataRef.set({
        refreshTime: new Date().getTime(),
        email: user.email,
        def_role: role
      });
    } catch (error) {
      throw new functions.https.HttpsError('internal', error.message);
    }
  }else{
    const metadataRef = admin.database().ref("metadata/" + user.uid);
    return await metadataRef.set({
      refreshTime: new Date().getTime(),
      email: user.email,
      def_role: "admin"
    });
  }
});
