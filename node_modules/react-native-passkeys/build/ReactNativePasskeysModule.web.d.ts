import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from "./ReactNativePasskeys.types";
interface CreationReponse extends Omit<RegistrationResponseJSON, "response"> {
    response: RegistrationResponseJSON["response"] & {
        /**
         * This operation returns an ArrayBuffer containing the DER SubjectPublicKeyInfo of the new credential, or null if this is not available.
         * https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-getpublickey
         */
        getPublicKey(): ArrayBuffer | null;
    };
}
declare const _default: {
    readonly name: string;
    isAutoFillAvalilable(): Promise<boolean>;
    isSupported(): boolean;
    create({ signal, ...request }: PublicKeyCredentialCreationOptionsJSON & Pick<CredentialCreationOptions, "signal">): Promise<CreationReponse | null>;
    get({ mediation, signal, ...request }: PublicKeyCredentialRequestOptionsJSON & Pick<CredentialRequestOptions, "mediation" | "signal">): Promise<AuthenticationResponseJSON | null>;
};
export default _default;
//# sourceMappingURL=ReactNativePasskeysModule.web.d.ts.map