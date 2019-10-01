//responsible for sending encrypted/normal file/message
function sendChatData(downloadLink,encryptedOnOff) {
    let message = '', encrytptedMessage = "",file = "false";
    let flag = 0;

	if(encryptedOnOff){
		if (downloadLink  != ""){
	        message = `<b>${userconnect.value}</b> : ${downloadLink}`;
	    	if(AESSessionKeyAtB && BPrivateKey != null){  
	            console.log("Encrypted file sent by B");   
	            var messageEncryptionFileatB = aesEncryption(message, AESSessionKeyAtB); 
	            encrytptedMessage = messageEncryptionFileatB;  
	            file = "true";   
	            flag = 1;               
	        }
	        else if(AESSessionKeyAtA && APrivateKey != null){
	             console.log("Encrypted file sent by A"); 
	             var messageEncryptionFileatA = aesEncryption(message, AESSessionKeyAtA);
	             encrytptedMessage = messageEncryptionFileatA;
	             file = "true";   
	        }      
	    }
	    else{
	        message = `<b>${userconnect.value}</b> : ${chatMessageElem.value}`;
	        if(AESSessionKeyAtB && BPrivateKey != null){  
	            console.log("Encrypted message sent by B");         
	            var messageEncryptionatB = aesEncryption(message, AESSessionKeyAtB); 
	            encrytptedMessage = messageEncryptionatB;     
	            flag = 1;         
	        }
	        else if(AESSessionKeyAtA && APrivateKey != null){
	             console.log("Encrypted message sent by A"); 
	             var messageEncryptionatA = aesEncryption(message, AESSessionKeyAtA);
	             encrytptedMessage = messageEncryptionatA; 
	        }
	    }
	    socket.emit('message:new', {flag,file,encryptedOnOff,encrytptedMessage});//emitting the message to the server
	}
	else{
		var fobj = "false";
		if (downloadLink  != ""){
			console.log("Normal file sent by sender");
	        message = `<b>${userconnect.value}</b> : ${downloadLink}`;
	        fobj = "true";
		}
		else{
			console.log("Normal message sent by sender");
			message = `<b>${userconnect.value}</b> : ${chatMessageElem.value}`;
		}
		socket.emit('message:new', {message,fobj});
	}
    chatMessageElem.value = "";
    chatMessageFileElem.value = "";
}

//a function to add the user names to the container to be displayed on the UI
function useronline(useronline) {
    const userItem = document.createElement('P');
    userItem.innerHTML = useronline;
    usronline.append(userItem)
}

//a function to add the messages to the container to be displayed on the UI
function addMessageToList(message) {
    const messageItem = document.createElement('P');
    messageItem.innerHTML = message;
    messageListContainerElem.append(messageItem)
}

//a function to upload the file using upload API
function uploadFile(file) {
    const data = new FormData();
    data.set('file', file);
    const url = 'http://localhost:3000/api/upload';
    return fetch(url, {
        method: 'POST',
        body: data
    });
}
//function calling the AES encrypt function of CryptoJS library 
function aesEncryption(message, password){
    var ciphertext = CryptoJS.AES.encrypt(message, password).toString();
    return ciphertext;
}
//function calling the AES decrypt function of CryptoJS library
function aesDecryption(crypted, password){
    var bytes  = CryptoJS.AES.decrypt(crypted, password);
    var originalText = bytes.toString(CryptoJS.enc.Utf8);
    return originalText;
}
//function calling the SHA function of CryptoJS library
function SHA256Hashing(message) {
    var digest = CryptoJS.SHA256(message);
    var digestString = CryptoJS.enc.Base64.stringify(digest);
    return digestString;
    }
//function used to generate RSA keys of JSEncrypt library
function rsaPrivatePublicKey(){
    var crypt = new JSEncrypt({ default_key_size: 1024 });
    return crypt.getKey();
}
//function to generate the digital signature using the CryptoJS library
function rsa2048Sign(message,privatekey){
    var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
    sig.init(privatekey);
    sig.updateString(message);
    var hSigVal = sig.sign();
    return hSigVal;
}
//function to verify the digital signature using the CryptoJS library
function rsa2048Verify(rsaSign,publickey,message){
    var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
    sig2.init(publickey);
    sig2.updateString(message);
    var isValid = sig2.verify(rsaSign);
    return isValid;
}
//function to generate the encryption using the RSA encrypt function of the JSEncrypt library
function rsa2048Encryption(message,keys){
    var crypt = new JSEncrypt({ default_key_size: 1024 });
    crypt.getKey();
    crypt.setPublicKey(keys);         
    var cipher = crypt.encrypt(message);
    return cipher;
}
//function to generate the encryption using the RSA decrypt function of the JSEncrypt library
function rsa2048Decryption(cipher,keys){
    var crypt = new JSEncrypt({ default_key_size: 1024 });
    crypt.getKey();
    crypt.setPrivateKey(keys);
    var decipher = crypt.decrypt(cipher);
    return decipher;
}




