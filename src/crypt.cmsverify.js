import * as asn1js from "asn1js";
import Certificate from "pkijs/src/Certificate";
import ContentInfo from "pkijs/src/ContentInfo";
import SignedData from "pkijs/src/SignedData";
import {convertPemToBinary, formatPEM} from "./crypto.pemutils";
import {arrayBufferToString, toBase64} from "pvutils";
import {certBegin, certEnd} from "./crypt.constants";


function verifyCMSSignedInternal(trustedCerts_pem, dataIn) {
    //region Initial check
    if (dataIn.byteLength === 0) {
        return Promise.reject("Nothing to verify!");
    }
    //endregion

    const trustedCerts = [];
    trustedCerts_pem.forEach((cert_pem)=>{
        const certAsn1 = asn1js.fromBER(convertPemToBinary(cert_pem));
        const certSimpl = new Certificate({schema: certAsn1.result});
        trustedCerts.push(certSimpl);
    });

    return Promise.resolve().then(() => {
            //region Decode existing CMS_Signed
        const cmsAsn1 = asn1js.fromBER(convertPemToBinary(dataIn));
        const cmsContentSimpl = new ContentInfo({schema: cmsAsn1.result});
        const cmsSignedSimpl = new SignedData({schema: cmsContentSimpl.content});
        //endregion

        //region Verify CMS_Signed
        const verificationParameters = {
            signer: 0,
            trustedCerts: trustedCerts
        };

        return cmsSignedSimpl.verify(verificationParameters).then((hasVerified) => {
                const result = {};
                result.signerCertificates = [];

                for (let i = 0; i < cmsSignedSimpl.certificates.length; i++) {
                    const certSimpl = new Certificate(cmsSignedSimpl.certificates[i]);
                    const certificateBuffer = certSimpl.toSchema(true).toBER(false);
                    const pem = `${certBegin}\n${formatPEM(toBase64(arrayBufferToString(certificateBuffer)))}\n${certEnd}`;
                    result.signerCertificates.push(pem);
                }

                result.dataOut = cmsSignedSimpl.encapContentInfo.eContent.valueBlock.toBER(false);
                result.hasVerified = hasVerified;
                return result;
            },
            error => {
                return `verifyCMSSignedInternal E001: ${error}`;
            }
        );
    });
    //endregion
}

//*********************************************************************************
export default function verifyCMSSigned(trustedCerts, dataIn) {
    //region Initial check
    try {
        if (dataIn.byteLength === 0) {
            Promise.reject("Nothing to verify!");
            return;
        }
    } catch (err) {
        Promise.reject("Nothing to verify!");
    }
    //endregion

    return verifyCMSSignedInternal(trustedCerts, dataIn).then((result) => {
            return result;
        },
        error => {
            return error;
        }
    );
}
