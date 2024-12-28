import SwiftRs
import CryptoKit
import LocalAuthentication

// reference:
// https://zenn.dev/iceman/scraps/380f69137c7ea2
// https://www.andyibanez.com/posts/cryptokit-secure-enclave/
@_cdecl("is_support_secure_enclave")
func isSupportSecureEnclave() -> Bool {
    return SecureEnclave.isAvailable
}

@_cdecl("generate_secure_enclave_p256_ecdh_keypair")
func generateSecureEnclaveP256KeyPairEcdh() -> SRString {
    return generateSecureEnclaveP256KeyPair(sign: false);
}

@_cdecl("generate_secure_enclave_p256_ecsign_keypair")
func generateSecureEnclaveP256KeyPairEcsign() -> SRString {
    return generateSecureEnclaveP256KeyPair(sign: true);
}

func generateSecureEnclaveP256KeyPair(sign: Bool) -> SRString {
    var error: Unmanaged<CFError>? = nil;
    guard let accessCtrl = SecAccessControlCreateWithFlags(
       nil,
       kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
       [.privateKeyUsage, .biometryCurrentSet],
       &error
    ) else {
        return SRString("err:\(error.debugDescription)")
    }
    do {
        if (sign) {
            let privateKeyReference = try SecureEnclave.P256.Signing.PrivateKey.init(
               accessControl: accessCtrl
            );
            let publicKeyBase64 = privateKeyReference.publicKey.x963Representation.base64EncodedString()
            let publicKeyPem = privateKeyReference.publicKey.derRepresentation.base64EncodedString()
            let dataRepresentationBase64 = privateKeyReference.dataRepresentation.base64EncodedString()
            return SRString("ok:\(publicKeyBase64),\(publicKeyPem),\(dataRepresentationBase64)")
        } else {
            let privateKeyReference = try SecureEnclave.P256.KeyAgreement.PrivateKey.init(
               accessControl: accessCtrl
            );
            let publicKeyBase64 = privateKeyReference.publicKey.x963Representation.base64EncodedString()
            let publicKeyPem = privateKeyReference.publicKey.derRepresentation.base64EncodedString()
            let dataRepresentationBase64 = privateKeyReference.dataRepresentation.base64EncodedString()
            return SRString("ok:\(publicKeyBase64),\(publicKeyPem),\(dataRepresentationBase64)")
        }
    } catch {
        return SRString("err:\(error)")
    }
}

@_cdecl("recover_secure_enclave_p256_ecsign_public_key")
func recoverSecureEnclaveP256PublicKeyEcsign(privateKeyDataRepresentation: SRString) -> SRString {
    return recoverSecureEnclaveP256PublicKey(privateKeyDataRepresentation: privateKeyDataRepresentation, sign: true);
}

@_cdecl("recover_secure_enclave_p256_ecdh_public_key")
func recoverSecureEnclaveP256PublicKeyEcdh(privateKeyDataRepresentation: SRString) -> SRString {
    return recoverSecureEnclaveP256PublicKey(privateKeyDataRepresentation: privateKeyDataRepresentation, sign: false);
}

func recoverSecureEnclaveP256PublicKey(privateKeyDataRepresentation: SRString, sign: Bool) -> SRString {
    guard let privateKeyDataRepresentation = Data(
        base64Encoded: privateKeyDataRepresentation.toString()
    ) else {
       return SRString("err:private key base64 decode failed")
    }
    do {
        let context = LAContext();
        if (sign)  {
            let privateKeyReference =  try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: privateKeyDataRepresentation,
                authenticationContext: context
            )
            let publicKeyBase64 = privateKeyReference.publicKey.x963Representation.base64EncodedString()
            let publicKeyPem = privateKeyReference.publicKey.derRepresentation.base64EncodedString()
            let dataRepresentationBase64 = privateKeyReference.dataRepresentation.base64EncodedString()
            return SRString("ok:\(publicKeyBase64),\(publicKeyPem),\(dataRepresentationBase64)")
        } else {
            let privateKeyReference =  try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: privateKeyDataRepresentation,
                authenticationContext: context
            )
            let publicKeyBase64 = privateKeyReference.publicKey.x963Representation.base64EncodedString()
            let publicKeyPem = privateKeyReference.publicKey.derRepresentation.base64EncodedString()
            let dataRepresentationBase64 = privateKeyReference.dataRepresentation.base64EncodedString()
            return SRString("ok:\(publicKeyBase64),\(publicKeyPem),\(dataRepresentationBase64)")
        }
    } catch {
        return SRString("err:\(error)")
    }
}

@_cdecl("compute_secure_enclave_p256_ecdh")
func computeSecureEnclaveP256Ecdh(privateKeyDataRepresentation: SRString, ephemeraPublicKey: SRString) -> SRString {
    guard let privateKeyDataRepresentation = Data(
        base64Encoded: privateKeyDataRepresentation.toString()
    ) else {
       return SRString("err:private key base64 decode failed")
    }
    guard let ephemeralPublicKeyRepresentation = Data(
        base64Encoded: ephemeraPublicKey.toString()
    ) else {
       return SRString("err:ephemeral public key base64 decode failed")
    }
    do {
        let context = LAContext();
        let p =  try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: privateKeyDataRepresentation,
            authenticationContext: context
        )

        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey.init(derRepresentation: ephemeralPublicKeyRepresentation)

        let sharedSecret = try p.sharedSecretFromKeyAgreement(
            with: ephemeralPublicKey)

        return SRString("ok:\(sharedSecret.description)")
    } catch {
        return SRString("err:\(error)")
    }
}

@_cdecl("compute_secure_enclave_p256_ecsign")
func computeSecureEnclaveP256Ecsign(privateKeyDataRepresentation: SRString, content: SRString) -> SRString {
    guard let privateKeyDataRepresentation = Data(
        base64Encoded: privateKeyDataRepresentation.toString()
    ) else {
       return SRString("err:private key base64 decode failed")
    }
    guard let contentData = Data(
        base64Encoded: content.toString()
    ) else {
       return SRString("err:content base64 decode failed")
    }
    do {
        let context = LAContext();
        let p =  try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: privateKeyDataRepresentation,
            authenticationContext: context
        )

        let digest = SHA256.hash(data: contentData)
        let signature = try p.signature(for: digest)

        return SRString("ok:\(signature.derRepresentation.base64EncodedString())")
    } catch {
        return SRString("err:\(error)")
    }
}