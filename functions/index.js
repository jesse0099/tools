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

// Not Recognized Action
class NotRecognizeAction extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.type = 'NotRecognizeAction';
  }
}

// Already treated account
class AlreadyTreatedAccount extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.type = 'AlreadyTreatedAccount';
  }
}

// Email Already in use
class EmailAlreadyInUse extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.type = 'EmailAlreadyInUse';
  }
}

// Funciones locales
// Roles permitidos
function roleIsValid(role) {
  const validRoles = ['admin', 'user', 'sa'];
  return validRoles.includes(role);
}

// Is Authenticated Checking
function isAuthenticatedCheck(context) {
  // Checking that the user calling the Cloud Function is authenticated
  return context.auth;
  // throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users can call this function.');
}
// Is Admin Checking
async function isAdminCheck(context) {
  // Checking that the user calling the Cloud Function is an Admin user or a super admin
  const callerUserRecord = await admin.auth().getUser(context.auth.uid);
  const caller_role = callerUserRecord.customClaims["https://hasura.io/jwt/claims"]["x-hasura-default-role"];

  var is_admin = false;
  if (caller_role === "admin" || caller_role === "sa")
    is_admin = true;
  return is_admin;
  // throw new NotAnAdminError('Only Admin users can read requests.');
}

// Email Already In Use
async function isEmailAlreadyInUse(email) {
  var is_in_use = false;
  await admin.auth().getUserByEmail(email).then(() => {
    is_in_use = true;
  }).catch(() => {
    is_in_use = false;
  });
  return is_in_use;
}
//Get Admin Creation Requests
exports.adminCreationRequests = functions.https.onCall(async (data, context) => {
  try {
    // Checking that the user calling the Cloud Function is authenticated
    if (!isAuthenticatedCheck(context))
      throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users can create new users.');

    // Checking that the user calling the Cloud Function is an Admin user
    if (! await isAdminCheck(context))
      throw new NotAnAdminError('Only Admin users can create new users.');

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
  const json_data = JSON.parse(data);
  const db = admin.firestore();
  const newUser = {
    email: json_data._adminAccountDetail.Email,
    emailVerified: false,
    password: json_data._adminAccountDetail.Password,
    displayName: json_data._adminAccountDetail.FirstName + ' ' + json_data._adminAccountDetail.LastName,
    disabled: false
  };
  var callerUid;
  try {
    var reject_request = false;
    // Checking that the user calling the Cloud Function is authenticated
    if (!isAuthenticatedCheck(context))
      throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users can create new users.');

    // Checking that the user calling the Cloud Function is an Admin user
    if (! await isAdminCheck(context))
      throw new NotAnAdminError('Only Admin users can create new users.');

    callerUid = context.auth.uid;  //uid of the user calling the Cloud Function

    // Checking that the new user role is valid
    const role = json_data._adminAccountDetail.Role;
    if (!roleIsValid(role))
      throw new InvalidRoleError('The "' + role + '" role is not a valid role');

    const userCreationRequestRef = admin.firestore()
      .collection("userCreationRequests").doc(json_data._docId);

    if (await isEmailAlreadyInUse(json_data._adminAccountDetail.Email))
      throw new EmailAlreadyInUse("This email is already in use by another account");


    // Begin Transaction
    await db.runTransaction(async (t) => {
      const doc = await t.get(userCreationRequestRef);
      const doc_status = doc.data().status;

      // Para simplificar, estoy tirando el mismo tipo de error para cualquier estado diferente de "Pending"
      if (doc_status !== "Pending")
        throw new AlreadyTreatedAccount("Already Treated Account");

      if (await isEmailAlreadyInUse(json_data._adminAccountDetail.Email))
        throw new EmailAlreadyInUse("This email is already in use by another account");

      await t.update(userCreationRequestRef, { status: 'Processing' });
    });
    // End Transaction
    admin.auth().createUser(newUser).then((user_record) => {
      const new_user_id = user_record.uid;
      const customClaims = {
        "https://hasura.io/jwt/claims": {
          "x-hasura-default-role": "admin",
          "x-hasura-allowed-roles": ["admin"],
          "x-hasura-user-id": new_user_id,
        },
      };
      (async () => await admin.auth().setCustomUserClaims(new_user_id, customClaims))().then(() => {
        userCreationRequestRef.update({ status: 'Treated', approvedBy: callerUid, accessGrantedBy: callerUid });
        return { message: "Admin created" };
      });
    });
  } catch (error) {
    if (error.type === 'UnauthenticatedError') {
      throw new functions.https.HttpsError('unauthenticated', error.message);
    } else if (error.type === 'NotAnAdminError' || error.type === 'InvalidRoleError' || error.type === 'AlreadyTreatedAccount') {
      throw new functions.https.HttpsError('failed-precondition', error.message);
    } else if (error.type === 'EmailAlreadyInUse') {
      const userCreationRequestRefErr = admin.firestore().collection("userCreationRequests").doc(json_data._docId);
      await db.runTransaction(async (t) => {
        reject_request = false;
        const doc = await t.get(userCreationRequestRefErr);
        const doc_status = doc.data().status;
        if (doc_status === "Pending") {
          await t.update(userCreationRequestRefErr, {
            status: 'Rejected', approvedBy: callerUid, motive: "This email is already in use by another account",
            accessGrantedBy: callerUid, enabled: false
          });
        }
      });
      throw new functions.https.HttpsError('failed-precondition', error.message);
    } else {
      throw new functions.https.HttpsError('internal', error.message);
    }
  }
});

// Admin Creation Rejection
exports.adminCreationRejection = functions.https.onCall(async (data, context) => {
  var callerUid;
  const db = admin.firestore();
  try {
    var already_treated = false;
    // Checking that the user calling the Cloud Function is authenticated
    if (!isAuthenticatedCheck(context))
      throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users can create new users.');

    // Checking that the user calling the Cloud Function is an Admin user
    if (! await isAdminCheck(context))
      throw new NotAnAdminError('Only Admin users can create new users.');

    callerUid = context.auth.uid;  //uid of the user calling the Cloud Function

    const json_data = JSON.parse(data);

    const userCreationRequestRef = admin.firestore().collection("userCreationRequests").doc(json_data._docId);

    // Begin Transaction
    await db.runTransaction(async (t) => {
      const doc = await t.get(userCreationRequestRef);
      const doc_status = doc.data().status;

      // Checking document state
      if (doc_status !== "Pending")
        throw new AlreadyTreatedAccount("Already Treated Account");

      await t.update(userCreationRequestRef, { status: "Rejected", approvedBy: callerUid, motive: json_data._motive, accessGrantedBy: callerUid, enabled: false });
      return { message: "User Rejected Successfully" };
    });
    // End Transaction

  } catch (error) {
    if (error.type === 'UnauthenticatedError') {
      throw new functions.https.HttpsError('unauthenticated', error.message);
    } else if (error.type === 'NotAnAdminError' || error.type === 'AlreadyTreatedAccount') {
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
    const collection_reference = admin.firestore().collection("userCreationRequests");
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
      enabled: true,
      accessGrantedBy: '',
    };

    const creation_reference = await admin.firestore().collection("userCreationRequests").add(userCreationRequest);

    await creation_reference.update({ docId: creation_reference.id });

  } catch (error) {
    if (error.type === "AlreadyTreatedAccount") {
      throw new functions.https.HttpsError('failed-precondition', error.message);
    } else {
      throw new functions.https.HttpsError('internal', error.message);
    }
  }
});

// Admin Access State Update
exports.adminAccessStateUpdate = functions.https.onCall(async (data, context) => {
  const json_data = JSON.parse(data);
  var already_disabled = false;
  var already_enabled = false;
  var user_uid, callerUid;
  try {
    // Checking that the user calling the Cloud Function is authenticated
    if (!isAuthenticatedCheck(context))
      throw new UnauthenticatedError('The user is not authenticated. Only authenticated Admin users modify users.');

    // Checking that the user calling the Cloud Function is an Admin user
    if (! await isAdminCheck(context))
      throw new NotAnAdminError('Only Admin users can access modify users state.');

    // Checking that the user calling the Cloud Function is an Admin user
    callerUid = context.auth.uid;  //uid of the user calling the Cloud Function

    switch (json_data.action) {
      case "enable": {
        await admin.auth().getUserByEmail(json_data.email)
          .then((user_record) => {
            user_uid = user_record.uid;
            if (!user_record.disabled)
              already_enabled = true;
          });

        if (already_enabled)
          throw new AlreadyTreatedAccount('Already Enabled Account');

        await admin.auth().updateUser(user_uid, { disabled: false })
          .then(() => {
            const doc_ref = admin.firestore().collection("userCreationRequests").doc(json_data.docId);
            (async () => doc_ref.update({ enabled: true, accessGrantedBy: callerUid, motive: '' }))()
              .then(() => {
                return { message: 'User Account Enabled' };
              });
          });
        break;
      }
      case "disable": {
        await admin.auth().getUserByEmail(json_data.email)
          .then((user_record) => {
            user_uid = user_record.uid;
            if (user_record.disabled)
              already_disabled = true;
          });

        if (already_disabled)
          throw new AlreadyTreatedAccount('Already Disabled Account');

        await admin.auth().updateUser(user_uid, { disabled: true })
          .then(() => {
            const doc_ref = admin.firestore().collection("userCreationRequests").doc(json_data.docId);
            (async () => doc_ref.update({ enabled: false, accessGrantedBy: callerUid, motive: json_data.motive }))()
              .then(() => {
                return { message: 'User Account Disabled' };
              });
          });
        break;
      }
      default: {
        throw new NotRecognizeAction("Not Recognized Action");
      }
    }
  } catch (error) {
    if (error.type === 'AlreadyTreatedAccount' || error.type === 'NotAnAdminError') {
      throw new functions.https.HttpsError('failed-precondition', error.message);
    } else {
      throw new functions.https.HttpsError('internal', error.message);
    }
  }
});

// On sign up.
exports.processSignUp = functions.auth.user().onCreate(async (user, context) => {
  var customClaims = {};
  var role;
  var isAdminRequest = false;
  var admin_creation_collection = admin.firestore().collection("userCreationRequests");
  // Create a query against the collection.
  //Consultar estado "Pendiente"
  const db = admin.firestore();

  var admin_creation_query = admin_creation_collection.where("userEmail", "==", user.email)
    .where("status", "==", "Processing");

  await db.runTransaction(async (t) => {
    isAdminRequest = false;
    const doc = await t.get(admin_creation_query);
    if (!doc.empty)
      isAdminRequest = true;
  });

  try {
    if (!isAdminRequest) {
      role = "user";
      customClaims = {
        "https://hasura.io/jwt/claims": {
          "x-hasura-default-role": "user",
          "x-hasura-allowed-roles": ["user"],
          "x-hasura-user-id": user.uid,
        },
      };

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
    } else {
      const metadataRef = admin.database().ref("metadata/" + user.uid);
      return await metadataRef.set({
        refreshTime: new Date().getTime(),
        email: user.email,
        def_role: "admin"
      });
    }
  } catch (error) {
    throw new functions.https.HttpsError('internal', error.message);
  }

});
