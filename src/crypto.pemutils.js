

const signAlgorithm = {
    name: "RSASSA-PKCS1-V1_5",
    hash: {
        name: "SHA-256"
    },
    //modulusLength: 2048,
    extractable: false,
    //publicExponent: new Uint8Array([1, 0, 1])
};


export function getParameters () {
    return signAlgorithm;
}

export function setParameters (newParameters) {
    Object.assign(signAlgorithm, newParameters);
}


export function formatPEM (pemString) {
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pemString" type="String">String to format</param>

    const stringLength = pemString.length;
    let resultString = "";

    for (let i = 0, count = 0; i < stringLength; i++, count++) {
        if (count > 63) {
            resultString = `${resultString}\n`;
            count = 0;
        }

        resultString = `${resultString}${pemString[i]}`;
    }

    return resultString;
}


function base64StringToArrayBuffer(b64str) {
    const byteStr = atob(b64str);
    const bytes = new Uint8Array(byteStr.length);
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
}

export function convertPemToBinary(pem) {
    const lines = pem.split('\n');
    let encoded = '';
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().length > 0 &&
            lines[i].indexOf('-BEGIN CERTIFICATE-') < 0 &&
            lines[i].indexOf('-BEGIN CMS-') < 0 &&
            lines[i].indexOf('-BEGIN PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-BEGIN PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END CERTIFICATE-') < 0 &&
            lines[i].indexOf('-END CMS-') < 0 &&
            lines[i].indexOf('-END PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
            encoded += lines[i].trim();
        }
    }
    return base64StringToArrayBuffer(encoded);
}


export function importPublicKey(pemKey, alg = signAlgorithm) {
    return new Promise(function (resolve) {
        const importer = crypto.subtle.importKey(
            "spki",
            convertPemToBinary(pemKey),
            alg,
            true,
            ["verify"]
        );
        importer.then(function (key) {
            resolve(key);
        });
    });
}


export function importPrivateKey(pemKey, alg = signAlgorithm) {
    return new Promise(function (resolve) {
        const importer = crypto.subtle.importKey(
            "pkcs8",
            convertPemToBinary(pemKey),
            alg,
            true,
            ["sign"]
        );
        importer.then(function (key) {
            resolve(key);
        });
    });
}


export function getRandom() {
    let array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return btoa(array);
}
