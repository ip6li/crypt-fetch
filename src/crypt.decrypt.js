import * as asn1js from "asn1js";
import Certificate from "pkijs/src/Certificate";
import EnvelopedData from "pkijs/src/EnvelopedData";
import {certificateDelimiter, cmsDelimiter, privateKeyDelimiter} from "./crypt.constants";
import {stringToArrayBuffer} from "pvutils";
import ContentInfo from "pkijs/src/ContentInfo";


function envelopedDecryptInternal(keyPair, dataIn) {
    const decryptPrms = {};

    decryptPrms.recipientPrivateKey = stringToArrayBuffer(window.atob(keyPair.privateKey.replace(privateKeyDelimiter, "")));

    if (typeof keyPair.certificate !== "undefined") {
        const certificateBuffer = stringToArrayBuffer(window.atob(keyPair.certificate.replace(certificateDelimiter, "")));
        decryptPrms.recipientCertificate = new Certificate({schema: asn1js.fromBER(certificateBuffer).result});
    }

    const cmsEnvelopedBuffer = stringToArrayBuffer(window.atob(dataIn.replace(cmsDelimiter, "")));
    const cmsContentSimpl = new ContentInfo({schema: asn1js.fromBER(cmsEnvelopedBuffer).result});
    const cmsEnvelopedSimp = new EnvelopedData({schema: cmsContentSimpl.content});

    const rcptIndex = 0;
    return cmsEnvelopedSimp.decrypt(rcptIndex, decryptPrms).then((result) => {
        return result;
    }).catch((err) => {
        return `envelopedDecryptInternal E001: ${err}`;
    });
}


export default function envelopedDecrypt(keyPair, dataIn) {
    return envelopedDecryptInternal(keyPair, dataIn).then((result) => {
        return result;
    }).catch((err) => {
        return `envelopedDecrypt E001: ${err}`;
    });
}
