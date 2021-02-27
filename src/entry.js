import genKey from "./crypt.genkey";
import createPKCS10 from "./crypt.csr";
import envelopedEncrypt from "./crypt.encrypt";
import envelopedDecrypt from "./crypt.decrypt";
import createCMSSigned from "./crypt.cmssign";
import verifyCMSSigned from "./crypt.cmsverify";
import {ConfigToolbox} from "./crypt.config";
import decrypt_and_verify from "./crypt.decrypt_and_verify";
import sign_and_encrypt from "./crypt.sign_and_encrypt";
import login from "./crypt.login";
import cryptFetch from "./crypt.cryptfetch";
import {getRandom} from "./crypto.pemutils";


class X509 {
    constructor(name, doRestoreConfig=false) {
        this.configToolbox = ConfigToolbox.getInstanceOf(name, doRestoreConfig);
        this.getConfig = function () { return this.configToolbox; };
        this.setConfig = function (newConfig) { this.configToolbox.setConfig(newConfig); };

        const defaultRequest = {
            method: 'POST', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'omit', // include, *same-origin, omit
            headers: {
                'Content-Type': 'application/json'
            },
            redirect: 'follow', // manual, *follow, error
            referrer: 'no-referrer', // no-referrer, *client
            body: JSON.stringify({}) // body data type must match "Content-Type" header
        };

        const defaultGetRequest = {
            method: 'GET', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'omit', // include, *same-origin, omit
            headers: {
                'Content-Type': 'application/json'
            },
            redirect: 'follow', // manual, *follow, error
            referrer: 'no-referrer' // no-referrer, *client
        };

        this.config = this.configToolbox.getConfig();
        this.config.defaultRequest = defaultRequest;
        this.config.defaultGetRequest = defaultGetRequest;
        this.configToolbox.setConfig(this.config);
    }

    genKey() {
        return genKey(this.getConfig());
    }

    createPKCS10(keyPair, request) {
        return createPKCS10(this.getConfig(), keyPair, request);
    }

    envelopedEncrypt(keyPair, plainTextArr, pem=true) {
        return envelopedEncrypt(this.configToolbox, keyPair, plainTextArr, pem);
    }

    envelopedDecrypt(keyPair, cms) {
        return envelopedDecrypt(keyPair, cms);
    }

    createCMSSigned(keyPairSign, plainTextArr) {
        return createCMSSigned(this.configToolbox, keyPairSign, plainTextArr);
    }

    verifyCMSSigned(trustedCerts, cmsSignedData) {
        return verifyCMSSigned(trustedCerts, cmsSignedData);
    }

    decrypt_and_verify (cms) {
        return decrypt_and_verify (this.configToolbox, cms);
    }

    sign_and_encrypt (plainText) {
        return sign_and_encrypt (this.configToolbox, plainText);
    }

    loadConfig(configURL, request=this.config.defaultGetRequest) {
        return fetch(configURL, request).then((response)=>{
            return response.json().then((data)=>{
                this.setConfig(data.config);
            });
        });
    }

    login(credentials) {
        return login (this.configToolbox, credentials).then((data) => {
            return data;
        });
    }

    cryptFetch (message) {
        return cryptFetch(this.configToolbox, message).then((data)=>{
            return data;
        });
    }

    renew () {
        const message = this.config.keystore.csr;
        return cryptFetch(this.configToolbox, message, true).then((data)=>{
            const decoded_data = JSON.parse(new TextDecoder("utf-8").decode(data.dataOut));
            this.config.keystore.certificate = decoded_data.crt;
            this.setConfig(this.config);
            return data;
        });
    }

    getRandom() {
        return getRandom();
    }
}


export default {
    X509
};
