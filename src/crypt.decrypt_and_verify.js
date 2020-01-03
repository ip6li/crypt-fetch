import envelopedDecrypt from "./crypt.decrypt";
import verifyCMSSigned from "./crypt.cmsverify";


export default function decrypt_and_verify (configToolbox, cms) {
    const config = configToolbox.getConfig();
    const localKeypair = {};
    localKeypair.privateKey = config.keystore.privateKey;
    localKeypair.certificate = config.keystore.certificate;
    const remoteKeypair = {};
    remoteKeypair.certificate = config.remotekeystore.server.replace("\\n", "\n");
    remoteKeypair.ca = config.remotekeystore.ca.replace("\\n", "\n");

    let sequence = Promise.resolve();

    sequence = sequence.then(()=>{
        return envelopedDecrypt(localKeypair, cms).then((decrypted)=>{
            return new TextDecoder("utf-8").decode(decrypted);
        });
    });

    sequence = sequence.then((decrypted_cms)=>{
        const trustedCerts = [remoteKeypair.ca];
        return verifyCMSSigned(trustedCerts, decrypted_cms).then((result)=>{
            return result;
        });
    });

    return sequence.then((result)=>{
        return result;
    });
}
