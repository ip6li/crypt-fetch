const assert = chai.assert;
const x509 = new MyX509("X509sessions", true);

describe('Crypto', function () {
    const refKeyPairRSA = {};
    // private key and certificate for tests for reference
    // created by OpenSSL
    refKeyPairRSA.privateKey = `-----BEGIN PRIVATE KEY-----
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
wSUT0pZ9teX/A9FBdVZR3yn1KBWVnGJp
-----END PRIVATE KEY-----`;

    refKeyPairRSA.certificate = `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIUA+kAup0l35VwaRdO+63tVSChlMkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJdGVzdC1jZXJ0MB4XDTE5MTIwNjA4NTcyNVoXDTI5MTIw
MzA4NTcyNVowFDESMBAGA1UEAwwJdGVzdC1jZXJ0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEA7GqsvMkXjiqnk/wocR/sMuvf5odJ5+i+KyF/5nn5q6tG
QJcDvhJJiOd/H5jVeC74QiTk3CDoNwKUuVukvkCpFkW5PDJ3VGTHLb6FrGN3pb7q
YcVRRoUvvPeBLcxGQXsL3+dacR9Gc9+h5JZ1H7uMmEgI2v1bwgNw9LXvZ3IpEe9g
mTRyqrpIzGLvsprMWWpr2nnyhrhSGoyzkM5dpspE8g7z9zTry52GBxHARz3SxEW9
5bR7qwt/TXEgd1ycKpPZWyeUUJDbRxmiqNM3uHmogSG9kBwfu4bCj1KmBO2wN88N
Dw2gmEdOQvFVkmltGbdBvDNfV0Q81bNFlFWwBvmdDRuxXyn/jWU2/tflJgY8imdR
EPmVJAVUYO2lsLkJJW92Tv74Z/7CKDwAG81MKPPgLa8GjtaLI9FSYMzmoFA0bmMK
GUyQcfnwJXjmQkd9Ku7C2JCh+IwSBzIdXY2l517nfrIwdc3S8IX76BK/RJM7mL9D
/ELQfxnUsHJJ3Q6eQ/gP/lnDRnup1nNen6etHjynZA3AVFI5yqoBKaGgxHS7VMP3
qoCMJrQkjhvzV5TTHAZj3NbIQPltM9e5NVPIKbw+1z1TYOlxwMJk7oCTOQ7xVz0k
a1+AUj4ciOsD75CjhGh0Jnrle+Nvm1YIyfVa36EOscSFf0Ro/GMhTVnmycXrZSkC
AwEAAaNmMGQwFAYDVR0RBA0wC4IJdGVzdC1jZXJ0MB0GA1UdDgQWBBTc8yN+eUo4
Cvc6VuquijenhDpYuDAfBgNVHSMEGDAWgBTc8yN+eUo4Cvc6VuquijenhDpYuDAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQBE4aCg5dRQ21YYGf/ci6pD
KHlsdueo7hgMX011jgA/ySYez0eIB9nfPXs/RLvnieA4KuJXPjSSmlfc3kWv3qw5
NQhIJEPRkTGE2wSYJ2i9VDgROGhSQALZYV3QaJ1w9D+W4iZSqXq+m0PN9A0tPpwl
SrrARh3OCsadsW6ihWiffi4sUjsPNkAJskMJWiPPRhGJL3KZfxdvncFZdpMkRQsS
BAIOlLhIzTNj8XxttA4BLgRSVBqdJvojK2F8EPTbPSdEKA1jfiCN5FRpC7TerQCt
m6X+/G74WaOMFXn+HTdUigLSFGmJZqwdlYRRg70kB5GJQnfSPqp5jkmmV7Af237H
s9EARc5PZ6mTApJamcnBeqmVSaz8i2kLKoTSL4119WufG8RcYr2MH7lOupdqYAY9
CdCpIPyGl03ML5uNgF85TeBFoy26guK0bIrQrH2PZTmnlC2DLt4DF7RmkySL5KiU
kSH8CZrpkLqWPgZzPtQ+UZbDRkwwRcvJfaHaMt/Z/6rT4q91p0RDSFRVepz9Vt3h
K7M9qCFhhzz8jMbI1CzbKicNcJycf1mQfMfj8TYtuOMzXb/dCjznYgqWpJRSdg5J
fT6QylzRb2rQTvSen2GhBWW9844M76XXGQAPMbMCWWNk/+eNmPqV9oWJivpKt6vU
gDy3iU6RHfWM8mw7JKO8WA==
-----END CERTIFICATE-----`;

    const refKeyPairRSAPSS = {};
    refKeyPairRSAPSS.privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAy06wvj3zhpjzUMrE
YsWnxDuutMtb0g572TBVBe8op3Za1Vd8QSu5NNdnuy5JCiHIojYtSJQE3J2VDDfz
mfYnxloON4zLOTWgzLNydeaW1zyQ8DNH02V59qWdME/biDk0ZRqzpGFAbgS1fHhy
tw5w1mHPePRfcgLbAJCXwlTe89nxJVt4dG1VlbfCF5hUveLos1NaJs7yufq5W+IM
giPBVQAbhDJnIKkfRAqjK4mgOVl4a4OTVYRMQ521rJgFiQu++FK8A8g/zdkqjGd9
auTh/5gdzHmyw2ZW6UryUQwt0KNiAbVSDYxF1p/YEkuEcf0EIE42LSooKHD0byxY
rv47UwIDAQABAoIBAQC5GPybR+X2rjwgW2tvDctPQpMt8VO4rA0f0PwnufUGeh/6
ynrLDtbBADhl158SBW4YGUEjKfg/L40qoao8izrtQMJe2uWPQX8Tv3C/XOAKOA8x
UU7cbTAcWe4BtUMHBCXqwuO5Df3N7KWbHEI83X3oAQcWdU6Mi4L+QaaZfBG8aheZ
R/N7/w4OcCM32K9G5+RxfDcf6kdcsem2vqlSU2rBaLLm6xJISE8ZuBMe9pM/VzpE
bXvYY4C2ORUUhYwMOxsOD562G2USWJWOLoLpuIpTRW+U8aQ2zvT3+K0iZIS4UPVb
+pL5DIda3CgmjyAsU7VB1ssaWQUWOOy8Tf3s+l9hAoGBAP0GxOW4TKVoGzIz3KSG
e1CXFcix5Rxm7k6RkFc+el+Et9ICBxzRrjoTquaKDbcjd1Qc0AVA6RjgeuxYbhxj
oqrNlFhPXp4i8BNrtdcHilg+1bvJ+8suyf+EXPFpcZGJ+pYJiPcd6Z0RzxdU3nMs
K0Mkr400+6DXumFHtznpi2mjAoGBAM2yV2E1yUPiZg2SFfSH+8F7Vg0kXdVZv8Hl
pvbBFQENGi0Qch70vGK5VXmF9A0z/e276HN+MYWCGMwB+hYr3wtVCDVIbezuq+iV
6fDNGWH32Z7nIn/j/PWqgXDrlBNYmWdmn5OEKCAwNmcib4OiLTy5/gztrZokD+cb
9uf8fWKRAoGBALIrRhKMiEwg1qWvJzsjB0pkWQ6NVct+H2hrz7vfXsRL7DSRAPkm
HQ0ANGNJ6wZ+jtRHxaMtZfYCfAxY6JBNCIpFYKQen32zFGJYgh78TEp/VHl7bTZR
qCOozNmhajsVccKczDlWct4LYEwJkup+u6f3+TXxjQ5hWfiOS1MYRPcJAoGBALVs
JcuUj/ay2YYAoiKySWdmbAhdWfGSHiJbdn7O38K0lrDGf5E0FHASvQPZFN8MS1wC
T0yGMhFqJIrS94vUl/47umicgG/oNnGGv/ZmP4v7+dJAVFpucK8Q+ufosAq8K1la
10ZZ2rZBL8qZQbfdM38LILqwa1y3j9sr/AKy3LgxAoGBAIyqIffyCiZKtJrSJPjk
w4CJ7Xf6FQmo+GYMmzCIcI9+tUz361whzSpfK6FV+D1IM4Zyx1sPcSapqnKtAzk/
dHq6vbHnK4XEE6kv0obNeG6XeLGuIOMzRb5Wb30kzV11DKl9+WRR4wSO4tiMTrly
Eld6LVPuJvUnasUO8A/WhMoS
-----END PRIVATE KEY-----`;
    refKeyPairRSAPSS.certificate = `-----BEGIN CERTIFICATE-----
MIIDbzCCAiagAwIBAgIUW32mAxM2z/1YYf2SfYwB3tIq5C0wPgYJKoZIhvcNAQEK
MDGgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogQC
AgDeMBYxFDASBgNVBAMMC1Rlc3QgUlNBUFNTMCAXDTE5MTIyNzEwMDk0NloYDzQ3
NTcxMTIyMTAwOTQ2WjAWMRQwEgYDVQQDDAtUZXN0IFJTQVBTUzCCASAwCwYJKoZI
hvcNAQEKA4IBDwAwggEKAoIBAQDLTrC+PfOGmPNQysRixafEO660y1vSDnvZMFUF
7yindlrVV3xBK7k012e7LkkKIciiNi1IlATcnZUMN/OZ9ifGWg43jMs5NaDMs3J1
5pbXPJDwM0fTZXn2pZ0wT9uIOTRlGrOkYUBuBLV8eHK3DnDWYc949F9yAtsAkJfC
VN7z2fElW3h0bVWVt8IXmFS94uizU1omzvK5+rlb4gyCI8FVABuEMmcgqR9ECqMr
iaA5WXhrg5NVhExDnbWsmAWJC774UrwDyD/N2SqMZ31q5OH/mB3MebLDZlbpSvJR
DC3Qo2IBtVINjEXWn9gSS4Rx/QQgTjYtKigocPRvLFiu/jtTAgMBAAGjUzBRMB0G
A1UdDgQWBBTMfFHbOidn5jf9jBwRSswSze721TAfBgNVHSMEGDAWgBTMfFHbOidn
5jf9jBwRSswSze721TAPBgNVHRMBAf8EBTADAQH/MD4GCSqGSIb3DQEBCjAxoA0w
CwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIEAgIA3gOC
AQEAIQG4pRawOz8jhD4uhTYos+RGJlEYuxKN0gRA2tQ+XMXyx6OrUOe09QvEPNiS
K6Le688mIWw6tJtl6E7el6EcZ7fKwWVONJ4sqpKGzXzpcYzlKUqyzfPdMKFYN/GR
RxgT+doh3FmCiQqKHBxOcCKjtOLLL7VYS+S0a8wZgAQf22RSNx9et9N410a4mzFp
zJGPvySNe9plQuFyawuxJNZUnn2vjIy7gfeqiAtlWu0KuH/xLJMCf+jnAh4rTW9Z
aATat1y0vyTPXProStp8yZ1ta2jlO2411alZoVT2g85eMy3M6F8nYjDlEEj+BE0d
P4HuC5nHEvot/3TPc348ty/SmQ==
-----END CERTIFICATE-----`;

    const plainText = "Hello world!\nThis is some test content.\nUTF-8 test with german umlauts: ÄÖÜäöüß€";
    const dump = document.getElementById("dump");
    dump.innerText = "";

    const id_debug = document.getElementById("debug");
    id_debug.innerText = "";


    function buf2hex(buffer) { // buffer is an ArrayBuffer
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join(' ');
    }

    before("Loading Config", async () => {
        const configURL = "http://127.0.0.1:8000/config";
        x509.loadConfig(configURL).then(() => {
            console.log("Config loaded");
        });
    });


    describe('TextEncoder class must resolve, because browser must support it', () => {
        it('should return a Promise resolve', async () => {
            let sequence = Promise.resolve();
            sequence = sequence.then(() => {
                const uint8array = new TextEncoder("utf-8").encode(plainText);
                const result = new TextDecoder().decode(uint8array);
                if (plainText === result) {
                    return Promise.resolve("result is equal to plainText");
                } else {
                    return Promise.reject("result is not equal to plainText");
                }
            });

            return await sequence;
        });
    });


    describe('Random generator', ()=>{
        it('Generates a random string:', async ()=>{
            const r = x509.getRandom();
            assert.ok(typeof r !== "undefined");
        });
    });

    describe('genKey: Creates a new key pair', () => {
        it('should return a Promise resolve and you should see a key pair', async () => {
            let sequence = Promise.resolve();

            const configToolbox = x509.getConfig();
            // do not use values beyond 4096, this kills Firefox even on powerful hardware
            if (!configToolbox.setModulus(2048)) {
                console.log ("failed to set modulus");
            }

            // create key pair
            sequence = sequence.then(() => {
                return x509.genKey().then((keyPair) => {
                    return keyPair;
                });
            });

            sequence = sequence.then((keyPair) => {
                dump.innerText = dump.innerText.concat(keyPair.privateKeyPEM.concat("\n\n", keyPair.publicKeyPEM));
            });

            return await sequence;
        }).timeout(10000).slow(500);
    });


    describe('Create PKCS#10 Certificate Signing Request', () => {
        it('should return a Promise resolve when CSR generation is successful', async () => {
            let sequence = Promise.resolve();

            sequence = sequence.then(() => {
                const request = {};
                request.cn = "Test CN";
                request.subjectAltNames = {};
                request.subjectAltNames.dNSName = ["san1", "san2"];

                return x509.createPKCS10(request).then((res) => {
                    const oldDump = dump.innerText;
                    dump.innerText = oldDump.concat("\n\n", res);
                    return res;
                });
            });

            return await sequence;
        }).slow(200);
    });

    describe('encryption and decryption', () => {
        it('should return a Promise resolve when encrypt -> decrypt sequence is successful and delivers same data before encryption', async () => {
            const keyPairEncrypt = {};
            keyPairEncrypt.certificate = refKeyPairRSA.certificate;
            let sequence = Promise.resolve();

            // let's do encrypt text
            sequence = sequence.then(() => {
                const plainTextArr = new TextEncoder().encode(plainText);
                return x509.envelopedEncrypt(keyPairEncrypt, plainTextArr).then((cms) => {
                    dump.innerText = dump.innerText.concat("\n\n", cms);
                    return cms;
                });
            });

            const keyPairDecrypt = {};
            keyPairDecrypt.privateKey = refKeyPairRSA.privateKey;
            sequence = sequence.then((cms) => {
                return x509.envelopedDecrypt(keyPairDecrypt, cms).then((text) => {
                    const decodedText = new TextDecoder().decode(text);
                    dump.innerText = dump.innerText.concat("\nDecrypted Text:\n", decodedText, "\n\n");
                    return decodedText;
                });
            });

            sequence = sequence.then((text) => {
                chai.assert(text === plainText, `plainText and decrypted text are not equal, plainText: ${plainText}, Decrypted text: ${text}`);
            });

            return await sequence;
        }).slow(500);
    });

    describe('signs and verifies a plain text with a pre seeded key/certificate', () => {
        it('should return a Promise resolve when sign -> verify sequence is successful and delivers successful verification', async () => {
            const signerKeyPair = refKeyPairRSA;
            const configToolbox = x509.getConfig();
            const config = configToolbox.config;
            //config.keyAlg.sign = "RSA-PSS";
            x509.setConfig(config);

            let sequence = Promise.resolve();

            sequence = sequence.then(() => {
                const keyPairSign = signerKeyPair;
                const plainTextArr = new TextEncoder().encode(plainText);
                return x509.createCMSSigned(keyPairSign, plainTextArr).then((signedData) => {
                    //id_debug.innerText = `x509.createCMSSigned:\n\n${signedData}`;
                    return signedData;
                });
            });

            sequence = sequence.then((cmsSignedData) => {
                const trustedCerts = [signerKeyPair.certificate];
                return x509.verifyCMSSigned(trustedCerts, cmsSignedData).then((result) => {
                    return result;
                });
            });

            sequence = sequence.then((result)=>{
                const dataOutText = new TextDecoder("utf-8").decode(result.dataOut).slice(2);
                dump.innerText = dump.innerText.concat("\nSigned Text:\n", dataOutText, "\n");
                dump.innerText = dump.innerText.concat("\nVerification result: ", result.hasVerified, "\n\n");

                chai.assert(dataOutText === plainText, ()=>{
                    return `Signed text does not match plain text \
                    \nlength plainText: ${plainText.length} \
                    \nplainText:\n${plainText} \
                    \nlength result.dataOut: ${dataOutText.length} \
                    \nresult.dataOut:\n${dataOutText} \
                    \nresult.dataOut Array:\n${buf2hex(result.dataOut)}`;
                });
                chai.assert(result.hasVerified, () => {
                    return `Validation failed \
                    \nlength plainText: ${plainText.length} \
                    \nplainText:\n${plainText} \\
                    \nlength result.dataOut:${dataOutText.length} \
                    \nresult.dataOut:\n${dataOutText} \
                    \nresult.dataOut Array:\n${buf2hex(result.dataOut)}`;
                });
            });

            return await sequence;
        }).timeout(10000).slow(1000);
    });

    describe('fetchCrypt - login to server (for test it signs CSR, only)', () =>{
        before(async ()=>{
            document.getElementById("username").value = "Username";
            document.getElementById("password").value = "Password";
            return await sendLogin();
        });
        it('fetchCrypt - signs and encrypts a message from client. Fetches a response from server, decrypt and verifies signature', async () => {
            console.log("old cert:\n%o", x509.getConfig().config.keystore.certificate);
            const testMsg = "Mocha: Hello world!";
            document.getElementById("message").value = testMsg;
            return await sendMessage().then((result)=>{
                result.decodedText = new TextDecoder("utf-8").decode(result.dataOut);
                chai.assert(
                    testMsg === result.decodedText,
                    `Test message is not identical to signed message\n${testMsg}\n${result.decodedText}`,
                    "Test message is identical to signed message\n"
                );
                chai.assert(result.hasVerified, "Verification failed\n", "Verification successful\n");
                console.log("fetchCrypt:\n%o", result);
            });
        }).timeout(2000).slow(1000);
    });

    describe('renew - try to renew certificate', () =>{
        it('send renew request - same as fetchCrypt, but renew flag is set to true', async ()=>{
            return await renew().then((data)=>{
                const decoded_data = JSON.parse(new TextDecoder("utf-8").decode(data.dataOut));
                console.log("renew:\n");
                console.log("new cert:\n%o", decoded_data.crt);
                return decoded_data;
            });
        }).timeout(5000).slow(800);
    });

});


const sendLogin = async function() {
    let sequence = Promise.resolve();

    const credentials = {};
    credentials.username = document.getElementById("username").value;
    credentials.password = document.getElementById("password").value;
    credentials.csr = x509.getConfig().config.keystore.csr;
    sequence = sequence.then(() => {
        return x509.login(credentials).then((data)=>{
            return data;
        });
    });

    sequence = sequence.then((data) => {
        return data;
    });

    return await sequence;
};


const sendMessage = async function() {
    const id_msg = document.getElementById("msg");
    id_msg.innerText = "";

    let sequence = Promise.resolve();

    const message = document.getElementById("message").value;

    sequence = sequence.then(() => {
        return x509.cryptFetch(message).then((data)=>{
            return data;
        });
    });

    sequence = sequence.then((data) => {
        id_msg.innerText = `${new TextDecoder("utf-8").decode(data.dataOut)}\n\n`;
        id_msg.innerText = id_msg.innerText.concat(`hasVerified: ${data.hasVerified}\n\n`);
        data.signerCertificates.forEach((cert)=>{
            id_msg.innerText = id_msg.innerText.concat(cert, "\n\n");
        });
        return data;
    });

    return await sequence;
};


const renew = async function() {
    let sequence = Promise.resolve();

    sequence = sequence.then(() => {
        return x509.renew().then((crt) => {
            return crt;
        });
    });

    return sequence.then((crt) => {
        return crt;
    });
};
