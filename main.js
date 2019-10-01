'use strict';
const formElem = document.getElementById('chat-form');
const chatMessageElem = document.getElementById('chat-message-input');
const chatMessageFileElem = document.getElementById('chat-file-input');
const messageListContainerElem = document.getElementById('message-list-container');
const userconnect = document.getElementById('usernames');
const userentry = document.getElementById('userentry');
const msgform = document.getElementById('msgdisplay');
const usronline = document.getElementById('user-container-list');
const encryptOn = document.getElementById('encyptionOn');
var EncryptionResult, userIdA ,userIdB ;
var Anewuser,Bnewuser,newname,newnametwo,randA,randB;
var password ,cipher,keys,AIdentificationSocketName,BIdentificationSocketName;
var APublicKey, APrivateKey, BPrivateKey, BPublicKey, AKeys, BKeys, rsaSignA,rsaSignB,receiveSignA,receiveSignB;
var AShaDigest,BShaDigest,receiveAPublicKey,receiveBPublicKey,AReceivingDigest,BReceivingDigest,receivingRandA,receivingRandB;
var protocolString1,protocolString2,finalAPublickKey;
var AESSessionKeyAtA,AESSessionKeyAtB,step3String8,flag=0;
var receiveHashA, receiveHashB,AHashedValue,AReceiveHashValue,ASessionKey,BSessionKey,sessionA,sessionB;

/*connection to socket*/
const socket = io();

/*connecting new users to server*/
socket.on('user:ReceiveSocket', data => {
    //call to protocol as the encryption checkbox was true
    if(data.check){
        if(data.step1 == null && data.step5 == null && data.step2 == null){
            /*step1: Initializing public key to each other post connection to server*/
            userIdA = data.userId; 
            receiveAPublicKey = data.APublicKey;
            receivingRandA = data.randA;
            AIdentificationSocketName = data.Anewuser;
            receiveSignA = data.rsaSignA;
            receiveHashA = data.AShaDigest;
            userIdB = data.userId; 
            receiveBPublicKey = data.BPublicKey;
            receivingRandB = data.randB;
            BIdentificationSocketName = data.Bnewuser;
            receiveSignB = data.rsaSignB;
            receiveHashB = data.BShaDigest;
            if((data.Anewuser)){
                 useronline(data.Anewuser);   
            }
            else {
                 useronline(data.Bnewuser);   
            }
               
        }
        /*step2:checking/verifying the nonce sent by A at B*/
        else if(data.step1 == 1 && BPrivateKey != null){
            var step2String1 = data.step1string5;
            var receivingRandALenRecieve = data.receivingRandALen;
            var step2string1Len = data.step1string1Len;
            var step2string2 = data.step1string2;
            var receiveAPublicKeyatB = data.receiveAPublicKey;
            var receiveHashAatB = data.receiveHashA;
            var withoutIdentificationName = step2String1.substr(step2string1Len);
            var AIdentificationSocketNameatB = data.AIdentificationSocketName;
            var decryptedCipherAtB = rsa2048Decryption(withoutIdentificationName, BPrivateKey);
            var withoutRandString = step2string2.substr(receivingRandALenRecieve);
            var hashVerifyAtB = rsa2048Verify(withoutRandString,receiveAPublicKeyatB,receiveHashAatB);          
            if(hashVerifyAtB){
                    console.log("The nonce sent by A is correct/verified at B");//session key kab at B
                    var atBRandA = step2string2.substr(0, receivingRandALenRecieve);
                    var step2String2 = String(randB) + String(atBRandA);
                    AESSessionKeyAtB = SHA256Hashing(step2String2);
                    console.log("Session Key at B: " + AESSessionKeyAtB);
                    /*step3: sending request from B to A*/
                    if(AESSessionKeyAtB != null){
                        var check = "true";
                        var step3String1 = SHA256Hashing(String(randB));
                        var step3String2 = aesEncryption(String(atBRandA), AESSessionKeyAtB);
                        var step3String3 = step3String1 + step3String2;
                        var step3String4 = rsa2048Sign(step3String3, BPrivateKey);
                        var step3String5 = randB + step3String2 + step3String4;
                        var step3String6 = SHA256Hashing(step3String5);
                        var step3String7 = rsa2048Encryption(step3String6, receiveAPublicKeyatB);
                        var BIdentificationSendToA = Bnewuser;
                        step3String8 = AIdentificationSocketNameatB + Bnewuser + step3String7;
                        var step2 = 1;
                       socket.emit('user:SentSocket', {check,BIdentificationSendToA,BPublicKey,step3String3,randB,step3String5,step3String2,step2string1Len,step3String8,step2});
                    }
            }
            else{
                    console.log("The nonce sent by A is not correct/verified at B");
            }  
        }
        /*step4: checking/verifying the nonce sent by B at A*/
        if(APrivateKey != null && data.step2 == 1){
             var step4String1 = data.step3String8;
             var step4String2len = data.step2string1Len;
             var step4String3 = data.step3String2;
             var step4String4 = data.step3String5;
             var randBatA = data.randB;
             var step3String3atA = data.step3String3;
             var BPublicKeyatA = data.BPublicKey;
             var BIdentificationSendToAatA = data.BIdentificationSendToA;
             var noIdentificationName = step4String1.substr(step4String2len);
             var step4String2 = rsa2048Decryption(noIdentificationName, APrivateKey); 
             var encryptednonceAAtBlen =  String(step4String3).length;
             var randBlength = String(randBatA).length;
             var digitalSignaturebyB = step4String4.substr(randBlength + encryptednonceAAtBlen);
             var hashVerifyAtA = rsa2048Verify(digitalSignaturebyB,receiveBPublicKey,step3String3atA);
             var check = "true";
             if(hashVerifyAtA){
                console.log("The nonce sent by B is correct/verified at A");
                var atARandB = step4String4.substr(0, randBlength);
                var step4String3 = String(randBatA) + String(randA);
                AESSessionKeyAtA = SHA256Hashing(step4String3);
                console.log("Session Key at A: " + AESSessionKeyAtA);//session key kab at A
                //step5: a to B verification step
                var step5String1 = Anewuser + BIdentificationSendToAatA;
                var step5String2 = aesEncryption(atARandB, AESSessionKeyAtA);
                var step5String3 = step5String1 + step5String2;
                var step5String1Len = String(step5String1).length;
                var step5 =1;
                socket.emit('user:SentSocket', {check,step5,step5String1Len,step5String3});
            }
            else{
                    console.log("The nonce sent by B is not correct/verified at A");
            }
        } 
        /*step6: final verification of the nonce of A at B using session key kab*/
        if(data.step5 && Anewuser == null){
            var step6String1 = data.step5String3;
            var step6String2Len = data.step5String1Len;
            var step6String4 = step6String1.substr(step6String2Len);
            var keyDecryptionCheck = aesDecryption(step6String4,AESSessionKeyAtB);
            console.log("Final verification of A Nonce at B: " + keyDecryptionCheck.toString(CryptoJS.enc.Utf8));
        }
    }
    //normal user connection and no call to protocol 
    else{
        if((data.Anewuser)){
             useronline(data.Anewuser);   
        }
        else {
             useronline(data.Bnewuser);   
        }
    }
});


//user event for adding users to sockets
 userentry.addEventListener('submit', event => {
    event.preventDefault();   
    /*Encryption on*/
    if(encryptOn.checked){
        var check = encryptOn.checked;
    
        if(userIdB == null){
            /*getting RSA private-public keys, digital signature and hashing for A and connecting to server*/
            randA = Math.random();
            AShaDigest = SHA256Hashing(randA.toString());
            AKeys = rsaPrivatePublicKey();
            APublicKey = AKeys.getPublicKey();
            APrivateKey = AKeys.getPrivateKey();
            rsaSignA = rsa2048Sign(AShaDigest,APrivateKey);
            Anewuser = `${userconnect.value}`;
            console.log(Anewuser);
            socket.emit('user:SentSocket', {check,Anewuser,APublicKey,randA,rsaSignA,AShaDigest});//emit is used to send the message entered by the sending socket     
        }
        else{
            /*getting RSA private-public keys, digital signature and hashing for B and connecting to server*/
            flag = 1;
            randB = Math.random();
            BShaDigest = SHA256Hashing(randB.toString());
            BKeys = rsaPrivatePublicKey();
            BPublicKey = BKeys.getPublicKey();
            BPrivateKey = BKeys.getPrivateKey();
            rsaSignB = rsa2048Sign(BShaDigest,BPrivateKey);
            Bnewuser = `${userconnect.value}`;
            console.log(Bnewuser);
            socket.emit('user:SentSocket', {check,Bnewuser,BPublicKey,randB,rsaSignB,BShaDigest});//emit is used to send the message entered by the sending socket     
        }  
        if(flag ==1){
            /*step1: formation of step1 protocol-sending from A to B*/
            var step1string1 = AIdentificationSocketName + Bnewuser;
            var step1string2 = receivingRandA + receiveSignA;
            var step1string3 = SHA256Hashing(step1string2);//reduccing the signature size for encryption
            var step1string4 = rsa2048Encryption(step1string3,BPublicKey);
            var step1string5 = step1string1 + step1string4;
            var step1string1Len = String(step1string1).length;
            var receivingRandALen = String(receivingRandA).length;
            var step1 = 1;
            console.log("Protocol start at A");
            socket.emit('user:SentSocket', {check,AIdentificationSocketName,receiveHashA,receiveAPublicKey,step1string2,receivingRandALen,step1string3,step1string1Len,step1string5,step1});
        }
    }
    /*Encryption off*/
    else{
        if(userIdB == null){
            /*user A details when connected to server*/
            Anewuser = `${userconnect.value}`;
            console.log(Anewuser);
            socket.emit('user:SentSocket', {Anewuser});
        } 
        else{
            /*user B details when connected to server*/
            Bnewuser = `${userconnect.value}`;
            console.log(Bnewuser);
            socket.emit('user:SentSocket', {Bnewuser});
        }
    }   
    userentry.style.display = 'none';
    msgform.style.display = 'block';
});

//socket for receiving message/file
socket.on('message:received', data => {
    var finalMessage = "";
    //decryption of the file or message sent
    if(data.encryptedOnOff){
        if(data.file == "true"){
            //file decryption at B
            if(AESSessionKeyAtB && BPrivateKey != null){  
                if(data.flag == 1){     
                    var messageDecryptionatB = aesDecryption(data.encrytptedMessage, AESSessionKeyAtB); 
                    finalMessage = messageDecryptionatB.toString(CryptoJS.enc.Utf8);     
                } 
                else{
                    console.log("Decrypted file at B sent by A");      
                    var messageDecryptionatB = aesDecryption(data.encrytptedMessage, AESSessionKeyAtB); 
                    finalMessage = messageDecryptionatB.toString(CryptoJS.enc.Utf8);  
                }
                        
            }
            //file decryption at A
            else if(AESSessionKeyAtA && APrivateKey != null){
                if(data.flag == 0){ 
                    var messageDecryptionatA = aesDecryption(data.encrytptedMessage, AESSessionKeyAtA);
                    finalMessage = messageDecryptionatA.toString(CryptoJS.enc.Utf8); 
                }
                else{
                    console.log("Decrypted file at A sent by B");  
                    var messageDecryptionatA = aesDecryption(data.encrytptedMessage, AESSessionKeyAtA);
                    finalMessage = messageDecryptionatA.toString(CryptoJS.enc.Utf8); 
                }
                
            }  
        }
        else{
            //message decryption at B
            if(AESSessionKeyAtB && BPrivateKey != null){   
                if(data.flag == 1){
                    var messageDecryptionatB = aesDecryption(data.encrytptedMessage, AESSessionKeyAtB); 
                    finalMessage = messageDecryptionatB.toString(CryptoJS.enc.Utf8);  
                }
                else{
                    console.log("Decrypted message at B sent by A");      
                    var messageDecryptionatB = aesDecryption(data.encrytptedMessage, AESSessionKeyAtB); 
                    finalMessage = messageDecryptionatB.toString(CryptoJS.enc.Utf8);  
                }                       
            }
            //message decryption at A
            else if(AESSessionKeyAtA && APrivateKey != null){
                if(data.flag == 0){
                    var messageDecryptionatA = aesDecryption(data.encrytptedMessage, AESSessionKeyAtA);
                    finalMessage = messageDecryptionatA.toString(CryptoJS.enc.Utf8);
                }
                else{
                    console.log("Decrypted message at A sent by B");  
                    var messageDecryptionatA = aesDecryption(data.encrytptedMessage, AESSessionKeyAtA);
                    finalMessage = messageDecryptionatA.toString(CryptoJS.enc.Utf8); 
                }
            }   
        }   
    }
    //normal flow without encryption
    else{
        //file receving
        if(data.fobj == 'true'){
            console.log("Normal file received by receiver");
            finalMessage = data.message;
        }
        //message receiving
        else{
            console.log("Normal message received by receiver");
            finalMessage = data.message;
        }    
    }
    addMessageToList(finalMessage);
});

//user event for submitting message/file 
formElem.addEventListener('submit', async (event) => {
    event.preventDefault();//default action of the event is prevented
    const file = chatMessageFileElem.files[0];//stores the filename which the sender 
    let encryptedOnOff = encryptOn.checked;
    let uploadedFilePath = '';
    let downloadLink = '';
    //check for file
    if (file) {
        try {
            var files = `${chatMessageFileElem.value}`;
            var finalfilename = files.substring(12);
            const res = await uploadFile(file);
            const result = await res.json();
            uploadedFilePath = result.path;
            if (uploadedFilePath) {
                downloadLink = `<a href="${uploadedFilePath}" target="_blank" download>${finalfilename}</a>`
            }           
        } catch (error) {
            console.error(error);
        }
    }
    sendChatData(downloadLink,encryptedOnOff);//calling this function for both file and message 
});  
    
