import type { AuthenticationExtensionsClientInputs as TypeScriptAuthenticationExtensionsClientInputs, Base64URLString, AuthenticatorTransportFuture, PublicKeyCredentialJSON, PublicKeyCredentialDescriptorJSON, PublicKeyCredentialUserEntityJSON, AuthenticatorAttestationResponseJSON } from "@simplewebauthn/typescript-types";
export type { AttestationConveyancePreference, AuthenticationCredential, AuthenticatorAssertionResponse, AuthenticatorAttachment, AuthenticatorAttestationResponse, AuthenticatorSelectionCriteria, AuthenticatorTransport, COSEAlgorithmIdentifier, Crypto, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity, RegistrationCredential, UserVerificationRequirement, } from "@simplewebauthn/typescript-types";
export type { Base64URLString, PublicKeyCredentialJSON, AuthenticatorTransportFuture, PublicKeyCredentialDescriptorJSON, PublicKeyCredentialUserEntityJSON, AuthenticatorAttestationResponseJSON, };
/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission
 *
 * This should eventually get replaced with official TypeScript DOM types when WebAuthn L3 types
 * eventually make it into the language:
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptionsjson
 */
export interface PublicKeyCredentialCreationOptionsJSON {
    rp: PublicKeyCredentialRpEntity;
    user: PublicKeyCredentialUserEntityJSON;
    challenge: Base64URLString;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    timeout?: number;
    excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    attestation?: AttestationConveyancePreference;
    extensions?: AuthenticationExtensionsClientInputs;
}
/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission
 */
export interface PublicKeyCredentialRequestOptionsJSON {
    challenge: Base64URLString;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptorJSON[];
    userVerification?: UserVerificationRequirement;
    extensions?: AuthenticationExtensionsClientInputs;
}
/**
 * A slightly-modified RegistrationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded so that they can be sent as JSON.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
 */
export interface RegistrationResponseJSON {
    id: Base64URLString;
    rawId: Base64URLString;
    response: AuthenticatorAttestationResponseJSON;
    authenticatorAttachment?: AuthenticatorAttachment;
    clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
    type: PublicKeyCredentialType;
}
/**
 * A slightly-modified AuthenticationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded so that they can be sent as JSON.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson
 */
export interface AuthenticationResponseJSON {
    id: Base64URLString;
    rawId: Base64URLString;
    response: AuthenticatorAssertionResponseJSON;
    authenticatorAttachment?: AuthenticatorAttachment;
    clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
    type: PublicKeyCredentialType;
}
/**
 * A slightly-modified AuthenticatorAssertionResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded so that they can be sent as JSON.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticatorassertionresponsejson
 */
export interface AuthenticatorAssertionResponseJSON {
    clientDataJSON: Base64URLString;
    authenticatorData: Base64URLString;
    signature: Base64URLString;
    userHandle?: string;
}
/**
 * TypeScript's types are behind the latest extensions spec, so we define them here.
 * Should eventually be replaced by TypeScript's when TypeScript gets updated to
 * know about it (sometime after 5.3)
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputs
 */
export interface AuthenticationExtensionsClientInputs extends TypeScriptAuthenticationExtensionsClientInputs {
    largeBlob?: AuthenticationExtensionsLargeBlobInputs;
}
export type LargeBlobSupport = "preferred" | "required";
/**
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationextensionslargeblobinputs
 */
export interface AuthenticationExtensionsLargeBlobInputs {
    support?: LargeBlobSupport;
    read?: boolean;
    write?: Base64URLString;
}
export interface AuthenticationExtensionsClientOutputs {
    largeBlob?: Omit<AuthenticationExtensionsLargeBlobOutputs, "blob"> & {
        blob?: ArrayBuffer;
    };
}
export interface AuthenticationExtensionsClientOutputsJSON {
    largeBlob?: AuthenticationExtensionsLargeBlobOutputs;
}
/**
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationextensionslargebloboutputs
 */
export interface AuthenticationExtensionsLargeBlobOutputs {
    supported?: boolean;
    blob?: Base64URLString;
    written?: boolean;
}
/**
 * A library specific type that combines the JSON results of a registration operation with a method
 * to get the public key of the new credential since these are not available directly from the native side
 */
export interface CreationReponse extends Omit<RegistrationResponseJSON, "response"> {
    response: RegistrationResponseJSON["response"] & {
        /**
         * This operation returns an ArrayBuffer containing the DER SubjectPublicKeyInfo of the new credential, or null if this is not available.
         * https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-getpublickey
         */
        getPublicKey(): Uint8Array | null;
    };
}
//# sourceMappingURL=ReactNativePasskeys.types.d.ts.map