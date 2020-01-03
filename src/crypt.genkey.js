import {getCrypto, getAlgorithmParameters} from "pkijs/src/common";
import {formatPEM} from "./crypto.pemutils";


function genKeyInternal(configToolbox) {
    const keyPair = {};
    let sequence = Promise.resolve();

    // begin load WebCrypto extension
    const crypto = getCrypto();
    if (typeof crypto === "undefined") {
        return Promise.reject("No WebCrypto extension found");
    }
    // end load WebCrypto extension

    // begin Create a new key pair
    sequence = sequence.then(() => {
        const keyAlg = configToolbox.getConfigKey("keyAlg");
        const algorithm = getAlgorithmParameters(keyAlg.sign, "generatekey");
        if ("hash" in algorithm.algorithm) {
            algorithm.algorithm.hash.name = keyAlg.hash;
        }
        algorithm.algorithm.modulusLength = parseInt(keyAlg.modulusLength);

        return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    });
    // end Create a new key pair

    // begin save keypair
    sequence = sequence.then(newKeyPair => {
        keyPair.privatekey = newKeyPair.privateKey;
        keyPair.publicKey = newKeyPair.publicKey;
    });
    // end save keypair

    // begin export private key as PEM
    sequence = sequence.then(() => {
        return crypto.exportKey("pkcs8", keyPair.privatekey);
    });

    sequence = sequence.then(result => {
        const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(result));
        const privateKeyResultString = "\r\n-----BEGIN PRIVATE KEY-----\r\n";
        keyPair.privateKeyPEM = privateKeyResultString.concat(
            formatPEM(window.btoa(privateKeyString)),
            "\r\n-----END PRIVATE KEY-----\r\n"
        );
    });
    // end export private key as PEM

    // begin export public key as PEM
    sequence = sequence.then(() => {
        return crypto.exportKey("spki", keyPair.publicKey);
    });

    sequence = sequence.then((result) => {
        const publicKeyString = String.fromCharCode.apply(null, new Uint8Array(result));
        const publicKeyResultString = "\r\n-----BEGIN PUBLIC KEY-----\r\n";
        keyPair.publicKeyPEM = publicKeyResultString.concat(
            formatPEM(window.btoa(publicKeyString)),
            "\r\n-----END PUBLIC KEY-----\r\n"
        );
        return keyPair;
    });
    // end export public key as PEM

    sequence = sequence.then((keyPair) => {
        configToolbox.setPrivateKey(keyPair.privateKeyPEM);
        configToolbox.setPublicKey(keyPair.publicKeyPEM);
        configToolbox.saveConfig();
        return keyPair;
    });

    return sequence.then((keyPair) => {
        return keyPair;
    });
}

//*********************************************************************************

export default function genKey(configToolbox) {
    const keyPairPEM = {};
    if (configToolbox.getDoRestoreConfiguration() &&
        typeof configToolbox.getPrivateKey() !== "undefined" &&
        typeof configToolbox.getPublicKey() !== "undefined") {
        keyPairPEM.privateKeyPEM = configToolbox.getPrivateKey();
        keyPairPEM.publicKeyPEM = configToolbox.getPublicKey();
        return Promise.resolve(keyPairPEM);
    } else {
        return genKeyInternal(configToolbox).then((keyPair) => {
            keyPairPEM.privateKeyPEM = keyPair.privateKeyPEM;
            keyPairPEM.publicKeyPEM = keyPair.publicKeyPEM;
            return keyPairPEM;
        });
    }
}
