# sample
TheAppKey is a cloud-based IRM service exposed over a simple API. Our model is based on end-user identity and no keys are uploaded or stored in our system. 
You use our service to protect meta-data by specifying a policy and access the secure content by authenticating to our service using an authorized identity. 
We are exposing the javascript based API first but we have java for android, native C, c# and objective-C versions as well. 

We have built few web-based applications using this API such as secure email and cloud files. All encrypt and decrypt operations are performed on the
client-side inside the user web browser. We don't see user data and our model is to separate the key management from the data path.

We offer authentication service and integrate with Google and Microsoft accounts. We also support registeration of any email and binding it to a 
google authenticator mobile app OTP and yubikey.

All accesses are logged and the API allows for enumeration of user events.

Access to secure content is dynamic and as an owner of the content you can modify authorization policy, block and restore access on a per-encrypted item.
The API also allows developers to bind multiple items to a single resource and apply a single policy through it. This is useful in case you want
to protect an entire folder tree where all files are encrypted relative to a single policy template. The policy is maintained in the service
and used during the decrypt call.

Applications can store upto 64 bytes of metadata as part of the secure policy blob on the encrypt call and obtain this app meta-data during the decrypt call.
For example, you may want to perform your own encryption and using our service for key management, authenticaiton, revocation and logging functionality.
The application content encryption key can be stored in this appdata field.

Finally, the sample is a good start on how to build very quickly data security into your application wihtout having to deal with the key management complexities.
