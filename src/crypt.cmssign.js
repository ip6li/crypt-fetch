import * as asn1js from "asn1js";
import {
    cmsBegin,
    cmsEnd,
    contentTypeDataID,
    contentTypesignedDataID, dgtIDsha1, messageDigestID, pkcs7ID, pkcs9ID, sha1withRSAid, signingTimeID
} from "./crypt.constants";
import Certificate from "pkijs/src/Certificate";
import SignedData from "pkijs/src/SignedData";
import EncapsulatedContentInfo from "pkijs/src/EncapsulatedContentInfo";
import SignerInfo from "pkijs/src/SignerInfo";
import IssuerAndSerialNumber from "pkijs/src/IssuerAndSerialNumber";
import ContentInfo from "pkijs/src/ContentInfo";
import {convertPemToBinary, formatPEM, importPrivateKey} from "./crypto.pemutils";
import {arrayBufferToString, toBase64} from "pvutils";
import Attribute from "pkijs/src/Attribute";
import SignedAndUnsignedAttributes from "pkijs/src/SignedAndUnsignedAttributes";
import {getAlgorithmByOID, getCrypto, getOIDByAlgorithm, PrivateKeyInfo} from "pkijs";
import AlgorithmIdentifier from "pkijs/src/AlgorithmIdentifier";


function genExtAttr(hashAlg, dataBuffer) {
    const crypto = getCrypto();

    let sequence = Promise.resolve();

    //region Create a message digest
    sequence = sequence.then(
        () => crypto.digest({ name: hashAlg }, new Uint8Array(dataBuffer))
    );
    //endregion

    //region Combine all signed extensions
    sequence = sequence.then(
        result =>
        {
            const signedAttr = [];

            signedAttr.push(new Attribute({
                type: pkcs9ID,
                values: [
                    new asn1js.ObjectIdentifier({ value: pkcs7ID })
                ]
            })); // contentType

            signedAttr.push(new Attribute({
                type: signingTimeID,
                values: [
                    new asn1js.UTCTime({ valueDate: new Date() })
                ]
            })); // signingTime

            signedAttr.push(new Attribute({
                type: messageDigestID,
                values: [
                    new asn1js.OctetString({ valueHex: result })
                ]
            })); // messageDigest

            return signedAttr;
        }
    );
    //endregion

    return sequence.then((attrs)=>{
        return attrs;
    });
}


function createCMSSignedInternal(configToolbox, keyPair, dataIn) {
    const config = configToolbox.getConfig();

    //region Initial variables
    let sequence = Promise.resolve();
    let cmsSignedSimpl;
    //endregion

    const asn1 = asn1js.fromBER(convertPemToBinary(keyPair.certificate));
    const certSimpl = new Certificate({schema: asn1.result});

    const asn1pkey = asn1js.fromBER(convertPemToBinary(keyPair.privateKey));
    const pkey_info = new PrivateKeyInfo({schema: asn1pkey.result});

    const signAlgorithm = {
        name: getAlgorithmByOID(pkey_info.privateKeyAlgorithm.algorithmId).name,
        extractable: false,
        hash: "SHA-256"
    };

    let pkey = {};
    sequence = sequence.then(() => {
        return importPrivateKey(keyPair.privateKey, signAlgorithm).then((key) => {
            pkey = key;
        });
    });

    sequence = sequence.then(()=>{
        return genExtAttr(config.keyAlg.hash, dataIn).then((attrs)=>{
            return attrs;
        });
    });

    //region Initialize CMS Signed Data structures and sign it
    sequence = sequence.then((extAttrs) => {
        cmsSignedSimpl = new SignedData({
            encapContentInfo: new EncapsulatedContentInfo({
                eContentType: contentTypeDataID, // "data" content type
                eContent: new asn1js.OctetString({valueHex: dataIn})
            }),
            signerInfos: [
                new SignerInfo({
                    sid: new IssuerAndSerialNumber({
                        issuer: certSimpl.issuer,
                        serialNumber: certSimpl.serialNumber
                    }),
                    digestAlgorithm: new AlgorithmIdentifier({ algorithm_id: signAlgorithm }), // SHA-1
                    signatureAlgorithm: new AlgorithmIdentifier({ algorithm_id: sha1withRSAid }), // RSA + SHA-1
                })
            ],
            certificates: [certSimpl]
        });

        cmsSignedSimpl.signerInfos[0].signedAttrs = new SignedAndUnsignedAttributes({
            type: 0,
            attributes: extAttrs
        });

        return cmsSignedSimpl.sign(pkey, 0, config.keyAlg.hash);
    });
    //endregion

    //region Create final result
    return sequence.then(() => {
            const cmsSignedSchema = cmsSignedSimpl.toSchema(true);

            const cmsContentSimp = new ContentInfo({
                contentType: contentTypesignedDataID,
                content: cmsSignedSchema
            });

            const _cmsSignedSchema = cmsContentSimp.toSchema();

            //region Make length of some elements in "indefinite form"
            _cmsSignedSchema.lenBlock.isIndefiniteForm = true;

            const block1 = _cmsSignedSchema.valueBlock.value[1];
            block1.lenBlock.isIndefiniteForm = true;

            const block2 = block1.valueBlock.value[0];
            block2.lenBlock.isIndefiniteForm = true;

            const block3 = block2.valueBlock.value[2];
            block3.lenBlock.isIndefiniteForm = true;
            block3.valueBlock.value[1].lenBlock.isIndefiniteForm = true;
            block3.valueBlock.value[1].valueBlock.value[0].lenBlock.isIndefiniteForm = true;
            //endregion

            return _cmsSignedSchema.toBER(false);
        },
        error => Promise.reject(`Error during signing of CMS Signed Data: ${error}`)
    );
    //endregion
}

//*********************************************************************************
export default function createCMSSigned(configToolbox, keyPair, dataIn) {

    return createCMSSignedInternal(configToolbox, keyPair, dataIn).then((dataOut) => {
        return `${cmsBegin}\n${formatPEM(toBase64(arrayBufferToString(dataOut)))}\n${cmsEnd}`;
    });
}
