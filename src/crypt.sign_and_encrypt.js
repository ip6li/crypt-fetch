import createCMSSigned from "./crypt.cmssign";
import envelopedEncrypt from "./crypt.encrypt";


export default function sign_and_encrypt (configToolbox, plainText) {
    const config = configToolbox.getConfig();
    const localKeypair = {};
    localKeypair.privateKey = config.keystore.privateKey;
    localKeypair.certificate = config.keystore.certificate;
    const remoteKeypair = {};
    remoteKeypair.certificate = config.remotekeystore.server.replace("\\n", "\n");

    let sequence = Promise.resolve();

    sequence = sequence.then(()=>{
        const plainTextArr = new TextEncoder().encode(plainText);
        return createCMSSigned(configToolbox, localKeypair, plainTextArr).then((cmsSigned)=>{
            return cmsSigned;
        });
    });

    sequence = sequence.then((cmsSigned)=>{
        const plainTextArr = new TextEncoder().encode(cmsSigned);
        return envelopedEncrypt(configToolbox, remoteKeypair, plainTextArr).then((encrypted)=>{
            return encrypted;
        });
    });

    return sequence.then((result)=>{
        return result;
    });
}
