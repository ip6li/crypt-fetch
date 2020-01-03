import envelopedEncrypt from "./crypt.encrypt";


export default function login(configToolbox, credentials) {
    const config = configToolbox.getConfig();

    let sequence = Promise.resolve();

    sequence = sequence.then(()=>{
        const remoteKeypair = {};
        remoteKeypair.certificate = config.remotekeystore.server.replace("\\n", "\n");
        const plainText = JSON.stringify(credentials);
        const plainTextArr = new TextEncoder().encode(plainText);
        return envelopedEncrypt(configToolbox, remoteKeypair, plainTextArr).then((encrypted)=>{
            return encrypted;
        });
    });

    sequence = sequence.then((encryptedCMS)=> {
        const request = config.defaultRequest;
        request.headers = { 'Content-Type': 'text/plain' };
        request.body = encryptedCMS;

        return fetch(config.authURL, request).then((response) => {
            return response.json().then((data)=>{
                return data;
            });
        });
    });

    return sequence.then((data)=>{
        config.keystore.certificate = data.crt;
        configToolbox.setConfig(config);
        return data;
    });
}
