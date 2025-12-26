import type { AuthenticationExtensionsLargeBlobInputs, AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from './ReactNativePasskeys.types';
export declare function isSupported(): boolean;
export declare function isAutoFillAvalilable(): boolean;
export declare function create(request: Omit<PublicKeyCredentialCreationOptionsJSON, 'extensions'> & {
    extensions?: {
        largeBlob?: AuthenticationExtensionsLargeBlobInputs;
    };
} & Pick<CredentialCreationOptions, 'signal'>): Promise<RegistrationResponseJSON | null>;
export declare function get(request: Omit<PublicKeyCredentialRequestOptionsJSON, 'extensions'> & {
    extensions?: {
        largeBlob?: AuthenticationExtensionsLargeBlobInputs;
    };
}): Promise<AuthenticationResponseJSON | null>;
//# sourceMappingURL=index.d.ts.map