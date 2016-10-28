/*
TheAppKey is a service that enable developer to encrypt, decrypt, manage and monitor access to data. The authorization to the encrypted data is performed using people identity.
There are no certificates or passwords in this api. You will use email addresses for authorization. Users can use their existing google or microsoft addresses to sign in  or register
any email with the service to create an account.

Applications that want to handle sensitive user data or share secrets can use this service to protect the data. The actual data is never sent to the service, the encrypt/decrypt operations 
are all performed in the client. The actual user data after encryption is provided to the application to store or share it in any way. 

The model allows control of the data by dynamically manipulating the authorization policy with the service. You can add new users to secure content without re-encrypting existing content or
block access to specific users or everyone.

You can set expiry time on the content after which the content is only accessible by its author.

Every access attempt is logged in the service and can be queried via the API to obtain all the records.

We have build secure email messaging service and secure google drive using this API. You can visit https://www.lockmagic.com to use it and learn more about the model and different actions.

A sample policy, some fields are read-only and others are application defined

{
   "id":"405241bd4a3d1b41b603fb033ff775df",          // every encrypt operation generates an unique id embedded as part of the secure policy token
  "role":"Owner",                                    // role of the user currently logged on requesting the call
  "blocked":0,                                       // is the content blocked or not. 1 -> author revoked access to everyone. 0 -> no revocation is in effect
  "members":"JonDoe@theappkey.com:E;info@lockmagic.com:V",  // list of authorized users and role of each user
  "author":"Sara.sample.user@hotmail.com",            // author identity. This is a verification that the encryption was originated by this user. 
  "notify":"",                                       // read-reciept list of email addresses. In this case none.
  "expiry":"11/03/2016 05:29:38",                   // expiry time 
  "label":"PureUSSDProtocol.docx",                 // any user friendly string. For files, it's file file name. For email it can be subject of message. Store whatever you like
  "filename":"PureUSSDProtocol.docx",              // filename captured during the encryption process. The actual encrypted file may be renamed but this is the original name
  "writer":"Sara.sample.user@hotmail.com",         // last writer of that modified this secure content. Not the same as author in some advanced scenarios such as virtual secure rooms
  "ruri":"",                                       // resource URI. You can store whatever you like
  "rid":"",                                       // resource id that this content belongs to. Again, store what you like
  "rname":"",                                    // display name of resource. THis can be folder full path of file
  "rpid":""                                      // resource policy id. This can be anything but very significant key because it enables a policy to be published on the service to control access to all content belonging to same resource policy id. You can have a single folder policy and all the files are linked to it.
  }


  API List:

    TheAppKey.Login                             // obtain access token by sign in user to service. User credentials are required
    TheAppKey.Register                          // create an account for a given email address. Account activiation is pending actual email verification by end-user that owns email
    TheAppKey.QueryContacts                     // query set of contacts and access roles that user specified

    TheAppKey.Encrypt                           // encrypt data using specified policy
    TheAppKey.Decrypt                           // decrypt data to obtain clear data and associated policy

    TheAppKey.QueryPolicy                       // query policy of encrypted content
    TheAppKey.SetPolicy                         // update policy of existing encrypted content and optionally register the new policy with service to override future accesses by others. Must be an Owner or Author
    TheAppKey.BlockAccess                       // block access to everyone except author of encrypted content. Must be an owner or author to perform this operation
    TheAppKey.RestoreAccess                     // revert access to normal access evaluation. Must be author to perform this operation

    TheAppKey.QueryEvents                       // query access events for the given signed in user.
*/

var appkey = null; // handle to instance of theappkey object

var username;
var contacts;
var usertoken;

window.onload = function () {
    var status = document.getElementById("status");
    // create api instance and bind a messaging area for it to display messages
    appkey = new TheAppKey({ statusdiv: status });
}

// this is the success handler for the encrypt call
// result is an object that wraps the actual secure data
// The api exposes few ways to convert the internal wrapped result object to blob, arraybuffer, uri string. In this example I'm using Blob
// Return: if true is returned then the api will cause the encrypted file to be download into the browser. Return false means no download and the callback handler consumed the
// secure data.
function EncryptCallbackHandler(result) {
    var securedatablob = appkey.BlobFromResult(result); // get a blob from the result, the blob will be the encrypted data.
    var status = document.getElementById("status");

    status.innerText = "Encrypt size: " + securedatablob.size; // display the size but in real code this will do something useful with the secure data
    return true; // true to cause download or false to not download encrypted file
}


// this is the success handler for the decrypt call
// result is an object that wraps the clear data, policy, mime type and filename specified during encryption phase
// The api again allows the result to be exposed as data URI, blob, arraybuffer depending of what the application is planning to do with the data
// Return: if true is returned then the api will cause the clear file to be downloaded into the browser. Return false means no download and the callback handler consumed the clear data.
function DecryptCallbackHandler(result) {

    var uri = appkey.UriFromResult(result); // Let's get a uri base64 encoded string of the clear data to display directly
    var status = document.getElementById("status"); // get status div to display the policy
    status.innerText = JSON.stringify(result.policy); // convert object into a string

    if (uri) {
        window.open(uri);
        return true; // don't download
    }

    return false; // cause content to download as a file
}


// Event handler for some files selected. We only look at the first file for this demo
function DoAction() {
    var files = document.getElementById("file").files;
    var status = document.getElementById("status");

    status.innerText = "Working..";

    for (var i = 0; i < files.length; i++) {

        var file = files[i];
        // test whether the file is a secure file or not. If secure we can decrypt otherwise encrypt
        if (appkey.IsSecureFile(file.name)) {

            // the api support the data format as File or ArrayBuffer. Here we are showing it as an arraybuffer by loading it ourself.
            // read file and call decrypt
            var r = new FileReader();
            r.onloadend = function (e) {
                // capture file data to decrypt
                var arrayBufferContent = e.target.result;

                // accesstoken is obtained from login method
                // data is the data to decrypt as File or ArrayBuffer
                // success is handler when file data is decrypted successfully
                // error and progress are the same suggests
                var options = {
                    accesstoken: usertoken,
                    data: arrayBufferContent,
                    success: DecryptCallbackHandler,
                    progress: function (e) {
                    },
                    error: function (e) {
                        alert("Decrypt failed with error: " + e.status + " " + e.message);
                    }
                };
                appkey.Decrypt(options); // call decrypt method
            };
            r.readAsArrayBuffer(file);

        } else {
            // if not secure file then ask the user to specify the list of users to authorize. Here I'm assume a single email address
            var acl = prompt("Please enter email of the user to authorize");
            acl = acl.replace(/\s/g, ''); // remove all spaces
            // verify email
            if (verifyemail(acl) != null) {
                alert("Invalid email: " + acl);
                return;
            }

            // for fun specify an expiry time after which other users can't access the content
            // create expiry date, use expiry of 1 week or 604800 seconds
            var expiry = null;
            if (true) {
                var date = new Date();
                date.setTime(date.getTime() + (604800 * 1000));
                expiry = date.toUTCString();
            }

            // options to encrypt. there are many more but for now let's keep it simple
            // Each user can have a role "Owner, Editor or Viewer". 
            // In this example we have two users. No need to explicity specify the author and will be added automatically as Owner.
            // The author is the email address of the logged in user.
            var options = {
                accesstoken: usertoken,
                data: file,
                users: [
                    { email: acl, role: "Editor" },
                    { email: "info@lockmagic.com", role: "Viewer" }
                ],
                expiry: expiry,
                success: EncryptCallbackHandler,
                progress: function (e) {
                },
                error: function (e) {
                    alert("Encrypt failed with error: " + e.status + " " + e.message);
                }
            };
            appkey.Encrypt(options);
        }

    }
    return false;
}

// action handler to query currently selected file encryption policy
function doQueryPolicy() {
    var files = document.getElementById("file").files;

    if (files.length == 0)
        return;

    // capture current file
    var file = files[0];
    var status = document.getElementById("status");
    status.innerText = "Working..";

    // ask for policy and display as string
    appkey.QueryPolicy({
        token: usertoken,
        data: file,
        success: function (result) {
            var status = document.getElementById("status");
            status.innerText = JSON.stringify(result);
        },
        error: function (e) {
            alert("error " + e.error + "<br>" + e.message);
        }
    });
}

// action handler to query access events for content authored by the logged in user
// result is a json formatted string which is an array of events and ipaddress location table
function doEvents() {
    var status = document.getElementById("status");
    status.innerText = "Working..";
    appkey.QueryEvents({
        token: usertoken,
        success: function (result) {
            var status = document.getElementById("status");
            status.innerText = result;
        },
        error: function (e) {
            alert("error " + e.error + "<br>" + e.message);
        }
    });
}

// Each user can store a set of contacts with the service. Here we query the current user contacts but an application may choose to get this information from any where.
// The interesting part here is that each contact has one of 3 access levels:
//    Trust - the specified user is a delegate and can access any other authored by the logged in user. Useful for users with multiple email addresses and delegation within small groups
//    Deny - the specified user is blocked from access any content authored by the logged in user. Useful to block specific users that you don't want to access any content  you have previosly shared with them
//    Allow - normal user and regular authorization process is evaluated. This is mainly useful so that the user don't have to type in the email address each time. Your application can do this and not
//            necessarily need to store this information with us
// You get back a json object with email address of logged in user and an array of contacts with each entry consists of email and access role
function doContacts() {
    var status = document.getElementById("status");
    status.innerText = "Working..";
    appkey.QueryContacts({
        token: usertoken,
        success: function (result) {
            var status = document.getElementById("status");
            status.innerText = JSON.stringify(result);
        },
        error: function (e) {
            alert("error " + e.error + "<br>" + e.message);
        }
    });
}

// use this method to register a new email. This will cause a link validation email to be sent by the service
function doRegister() {
    var email = document.getElementById("email").value;
    if (email == null || email.length == 0) {
        alert("Please enter email");
        return;
    } else if (verifyemail(email) == false) {
        alert("Invalid email");
        return;
    }

    // you can register different authentication methods such as yubikey or authenticator OTP. For now keep it simple and show passsword as registration request
    appkey.Register({
        email: email,
        method: "password",
        success: function (e) {
            alert(e.message);
        },
        error: function (e) {
            alert("error " + e.error + "<br>" + e.message);
        }
    });

}// Action handler for login using username and password stored in our service.function LoginUser() {
    var email = document.getElementById("email").value;
    if (email == null || email.length == 0) {
        alert("Please enter email");
        return;
    } else if (verifyemail(email) == false) {
        alert("Invalid email");
        return;
    }
    var password = document.getElementById("password").value;
    if (password == null || password.length < 1) {
        alert("Please enter a valid password");
        return;
    }
    var options = {
        username: email,
        password: password,
        success: function (e) {
            // the result captures the user token that we need to the rest of the calls
            usertoken = e.token;
            username = email;
            document.getElementById('login').style.display = 'none';
            document.getElementById('drop').style.display = 'block';
        },
        error: function (e) {
            alert("Unable to login " + e.status + " " + e.message);
        }
    };

    appkey.Login(options);
}

// when authenticating the user using google or microsoft accounts we will get called back by the popup window with the user token.
window.addEventListener("message", function (event) {
    var token = event.data;
    usertoken = token; // capture token
    
    // switch view from login to actions
    document.getElementById('login').style.display = 'none';
    document.getElementById('drop').style.display = 'block';

    // capture token with appkey instance
    appkey.Init({ usertoken: token });
}
);

// user selected google or microsoft to login. Initiate a login sequence with a popup windowfunction startLogin(provid) {
    appkey.LaunchLoginWindow(provid);
}