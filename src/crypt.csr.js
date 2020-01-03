import * as asn1js from "asn1js";
import {
    csrBegin,
    csrEnd,
    oid,
    oidAltNames,
    pkcs_9_at_extensionRequest,
    extnID,
    sessionName, sanID
} from "./crypt.constants";
import {arrayBufferToString, toBase64} from "pvutils";
import Attribute from "pkijs/src/Attribute";
import CertificationRequest from "pkijs/src/CertificationRequest";
import Extension from "pkijs/src/Extension";
import GeneralNames from "pkijs/src/GeneralNames";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import GeneralName from "pkijs/src/GeneralName";
import Extensions from "pkijs/src/Extensions";
import {getCrypto} from "pkijs/src/common";
import {formatPEM, importPrivateKey, importPublicKey} from "./crypto.pemutils";


function createPKCS10Internal(configToolbox, keyPair, request) {
    const crypto = getCrypto();
    const pkcs10 = new CertificationRequest();

    pkcs10.version = 0;
    for (let key in request) {
        if (request.hasOwnProperty(key) && typeof oid[key] !== "undefined") {
            //noinspection JSPotentiallyInvalidConstructorUsage
            pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
                type: oid[key].type,
                value: new oid[key].asn1type({value: request[key]})
            }));
        }
    }
    pkcs10.attributes = [];

    let sequence = Promise.resolve();

    sequence = sequence.then(() => {
        if (typeof keyPair.privateKeyPEM !== "undefined") {
            return importPrivateKey(keyPair.privateKeyPEM).then((key) => {
                keyPair.privateKey = key;
            });
        }
    });

    sequence = sequence.then(() => {
        if (typeof keyPair.publicKeyPEM !== "undefined") {
            return importPublicKey(keyPair.publicKeyPEM).then((key) => {
                keyPair.publicKey = key;
            });
        }
    });

    sequence = sequence.then(() => {
        pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    });

    sequence = sequence.then(() => crypto.digest(
        {name: configToolbox.getConfig().keyAlg.hash},
        pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex)
    ).then(result => {
            pkcs10.attributes.push(new Attribute({
                type: pkcs_9_at_extensionRequest,
                values: [(new Extensions({
                    extensions: [
                        new Extension({
                            extnID: extnID,
                            critical: false,
                            extnValue: (new asn1js.OctetString({valueHex: result})).toBER(false)
                        })
                    ]
                })).toSchema()]
            }));
        }
    );

    //region add subjectAltname
    const altNameArray = [];
    if (request.subjectAltNames) {
        for (let key in request.subjectAltNames) {
            if (request.subjectAltNames.hasOwnProperty(key) && oidAltNames.hasOwnProperty(key)) {
                const type = oidAltNames[key].type;
                request.subjectAltNames[key].forEach((sanEntry) => {
                    altNameArray.push(
                        new GeneralName({
                            type: parseInt(type),
                            value: sanEntry
                        })
                    );
                });
            }
        }

        const altNames = new GeneralNames({
            names: altNameArray
        });

        pkcs10.attributes.push(new Attribute({
            type: pkcs_9_at_extensionRequest,
            values: [
                (new Extensions({
                    extensions: [
                        new Extension(
                            {
                                extnID: sanID,
                                critical: false,
                                extnValue: altNames.toSchema().toBER()
                            }
                        )
                    ]
                })).toSchema()]
        }));
    }
    //endregion

    //region Signing final PKCS#10 request
    sequence = sequence.then(
        () => pkcs10.sign(keyPair.privateKey, configToolbox.getConfig().keyAlg.hash),
        error => Promise.reject(`Error during exporting public key: ${error}`)
    );
    //endregion

    return sequence.then(() => {
        request.pkcs10Buffer = pkcs10.toSchema().toBER(false);

    }, error => Promise.reject(`Error signing PKCS#10: ${error}`));
}


//*********************************************************************************

export default function createPKCS10(configToolbox, request) {
    const keyPair = {};
    keyPair.privateKeyPEM = configToolbox.getPrivateKey();
    keyPair.publicKeyPEM = configToolbox.getPublicKey();
    return Promise.resolve().then(() => createPKCS10Internal(configToolbox, keyPair, request)).then(() => {
        const resultString = `${csrBegin}\n${formatPEM(toBase64(arrayBufferToString(request.pkcs10Buffer)))}\n${csrEnd}`;
        request.pkcs10 = resultString;
        configToolbox.setCsr(resultString);
        configToolbox.saveConfig();
        return resultString;
    }, error => Promise.reject(`${error}`));
}
