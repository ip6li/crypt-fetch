import * as asn1js from "asn1js";
import {certificateDelimiter, cmsBegin, cmsEnd, envelopedDataID, sessionName} from "./crypt.constants";
import {arrayBufferToString, toBase64, stringToArrayBuffer, fromBase64} from "pvutils";
import Certificate from "pkijs/src/Certificate";
import EnvelopedData from "pkijs/src/EnvelopedData";
import ContentInfo from "pkijs/src/ContentInfo";
import {formatPEM} from "./crypto.pemutils";


const envelopedEncryptInternal = function (configToolbox, keyPair, dataIn) {
    const config = configToolbox.getConfig();

    const certificateBuffer = stringToArrayBuffer(fromBase64(keyPair.certificate.replace(certificateDelimiter, "")));
    const certSimpl = new Certificate({schema: asn1js.fromBER(certificateBuffer).result});

    const cmsEnveloped = new EnvelopedData();
    const cmsEnvelopedParameters = {};
    cmsEnvelopedParameters.oaepHashAlgorithm = "SHA-256"; // The hash algorithm to be used with with RSASSA-OAEP
    //cmsEnvelopedParameters.kdfAlgorithm = "SHA-256"; // The hash algorithm to be used when deriving keys for use with ECDH
    //cmsEnvelopedParameters.kekEncryptionLength = 256; // The length of the key to be use with AES-KW
    cmsEnveloped.addRecipientByCertificate(certSimpl, cmsEnvelopedParameters);
    return cmsEnveloped.encrypt(config.encAlg, dataIn).then(() => {
            const cmsContentSimpl = new ContentInfo();
            cmsContentSimpl.contentType = envelopedDataID;
            // noinspection JSValidateTypes
            cmsContentSimpl.content = cmsEnveloped.toSchema();

            return cmsContentSimpl.toSchema().toBER(false);
        },
        error => {
            return `E001: ${error}`;
        }
    );
};

//*********************************************************************************
export default function envelopedEncrypt(configToolbox, keyPair, dataIn) {
    return envelopedEncryptInternal(configToolbox, keyPair, dataIn).then((cmsEnvelopedBuffer) => {
            return `${cmsBegin}\n${formatPEM(toBase64(arrayBufferToString(cmsEnvelopedBuffer)))}\n${cmsEnd}`;
        },
        error => Promise.reject(`ERROR DURING ENCRYPTION PROCESS: ${error}`)
    );

}
