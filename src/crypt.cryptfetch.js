import sign_and_encrypt from "./crypt.sign_and_encrypt";
import decrypt_and_verify from "./crypt.decrypt_and_verify";

export default function cryptFetch (configToolbox, message, renew=false) {
    const config = configToolbox.getConfig();

    let sequence = Promise.resolve();

    const plainText = JSON.stringify(message);

    sequence = sequence.then(()=>{
        return sign_and_encrypt(configToolbox, plainText).then((encrypted_text)=>{
            return encrypted_text;
        });
    });

    sequence = sequence.then((encryptedCMS)=> {
        const request = config.defaultRequest;
        let url = config.messageURL;
        if (renew) {
            url = config.renewURL;
        }
        request.headers = { 'Content-Type': 'text/plain' };
        request.body = encryptedCMS;
        return fetch(url, request).then((response) => {
            return response.json().then((data)=>{
                return decrypt_and_verify(configToolbox, data).then((result)=>{
                    return result;
                });
            });
        });
    });

    return sequence.then((encrypted)=>{
        return encrypted;
    });
}
