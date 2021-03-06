/* OpenPGP JavaScript Message Encryption (re-coded) */
/* Powered by www.haneWIN.net */

var keyid = '30a6a7bd5d56d8ee';
var pubkey = 'CADFaia+wLb74MMEx6F+WiX3jXw3Aa34VOuNb3VnvMwtjBJqzMcQdXqJ/gsMlY/7DJDPIwHGwybi8RmBz50nt7rCqB4/WwvoPXCeXpFzAKXi2bvyAlRJrFCg5aonJUqXlsrlag03HiiO7gVRaXEmQZOGCm4sG5jd8hgL9aqMSNmB+q0ZXwkMfS/xz3lMJyXrvNe+RhETqDQb/lsuHNaX4DyxhggEhZ+aSK8M9u1ptdRGgpKNpYYPTMZziN5VtG62f56jU9oY5NOaFMvu7EtS+OLUSn+5ZYPLer18VGKWue1M2GrogCZOJCzZv22nFrX+80md/dgu3/v70R3uviA9AUazABEBAAE='; // PubKey Multi Precision Integer (base64)


function encrypt(){

    if(document.getElementById('_name').value.length < 1
       || document.getElementById('_email').value.length < 6
       || document.getElementById('_message').value.length < 1){
        document.getElementById('_sendbtn').disabled = false;
        alert('Fill the fields correctly.');
        return;
    }   
    
    if(keyid.length != 16){
	    alert('Invalid Key Id.');
	    return;
    }  

    document.getElementById('_sendbtn').value = "Encrypting...";
    var text = document.getElementById('_message').value+'\r\n';
    document.getElementById('_message').value = doEncrypt(keyid, 0, pubkey, text);
    document.getElementById('_sendbtn').value = "Sending...";
    
    setTimeout(function(){
        document.getElementById('contactform').submit();
        document.getElementById('_name').value = "";
        document.getElementById('_email').value = "";
        document.getElementById('_message').value = "";
        document.getElementById('_sendbtn').value = "Send";
        document.getElementById('_sendbtn').disabled = false;
    }, 2000);

}

