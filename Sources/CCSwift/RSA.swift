import CCWrapper
import Foundation

public enum RSA {
    public struct PrivateKey: CustomStringConvertible {
        public var description: String {
            "<RSA Private Key of \(size) bits>"
        }
        
        public typealias Components = (modulus: Data, exponent: Data, p: Data, q: Data)
        
        internal var reference: CCRSACryptorRef?
        
        /// The size of the key in bits.
        public var size: Int {
            CCRSAGetKeySize(reference)
        }
        /// The components of this key (modulus, exponent).
        public var components: Components {
            let components = try! CCRSAGetKeyComponents(key: reference)
            return (components.modulus, components.exponent, components.p!, components.q!)
        }
        /// The public key of this private key.
        public var publicKey: RSA.PublicKey {
            return RSA.PublicKey(reference: CCRSACryptorGetPublicKeyFromPrivateKey(privateKey: reference))
        }
        
        /// The PKCS#1 formatted data of the key.
        public var PKCS1: Data {
            try! CCRSACryptorExport(key: reference)
        }
        /// The PEM encoded string of the key.
        public var PEM: String {
            return rsaPrivatePEMHeader + PKCS1.base64EncodedString(options: .lineLength64Characters) + rsaPrivatePEMFooter
        }
        
        /// Initialize an RSA private key for given size and exponent.
        /// - Parameters:
        ///   - size: The Key size in bits. RSA keys smaller than 2048 bits are insecure and should not be used.
        ///   - exponent: The exponent value. Must be odd. 65537 or larger.
        public init(size: Int, exponent: UInt32 = 65537) throws {
            var publicRef: CCCryptorRef?
            try CCRSACryptorGeneratePair(keySize: size, e: exponent, publicKey: &publicRef, privateKey: &reference)
        }
        
        /// Initialize an RSA private key from PKCS#1 data.
        /// - Parameter pkcs1: The PKCS#1 formatted data.
        public init(pkcs1: Data) throws {
            try CCRSACryptorImport(keyPackage: pkcs1, key: &reference)
            guard CCRSAGetKeyType(reference) == .private else { throw CryptoError.invalidKey }
        }
        
        /// Initialize the key from its PEM format.
        /// - Parameter pem: The PEM encoded data.
        public init(pem: String) throws {
            let trimmed = pem.replacingOccurrences(of: rsaPublicPEMHeader, with: "").replacingOccurrences(of: rsaPublicPEMFooter, with: "")
            guard let der = Data(base64Encoded: trimmed, options: .ignoreUnknownCharacters) else {
                throw CryptoError.decodeError
            }
            try self.init(pkcs1: der)
        }
        
        /// /// Initialize the key from its components.
        /// - Parameters:
        ///   - modulus: The modulus.
        ///   - exponent: The exponent.
        ///   - p: The modulus factor P data.
        ///   - q: The modulus factor Q data.
        public init(modulus: Data, exponent: Data, p: Data, q: Data) throws {
            try CCRSACryptorCreateFromData(type: .public, modulus: modulus, exponent: exponent, p: p, q: q, reference: &reference)
            guard CCRSAGetKeyType(reference) == .private else { throw CryptoError.invalidKey }
        }
        
        /// Sign data.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - padding: The signature padding scheme.
        /// - Returns: The signature.
        public func sign(_ data: Data, padding: Asymmetric.Padding) throws -> Data {
            var algorithm: Digest.Algorithm
            var saltSize: Int = 0
            switch padding {
            case .PKCS1(let a):
                algorithm = a
            case .PSS(let a, let s):
                algorithm = a
                saltSize = s
            default: throw CryptoError.paramError
            }
            return try CCRSACryptorSign(privateKey: reference, padding: padding.rawValue, data: data, digest: algorithm.rawValue, saltSize: saltSize)
        }
        
        /// Decrypt data.
        /// - Parameters:
        ///   - data: The data to decrypt.
        ///   - padding: The encryption padding scheme.
        /// - Returns: The decrypted data.
        public func decrypt(_ data: Data, padding: Asymmetric.Padding) throws -> Data {
            var algorithm: Digest.Algorithm
            var tag: Data? = nil
            switch padding {
            case .PKCS1(_):
                algorithm = .none
            case .OAEP(let a, let t):
                algorithm = a
                tag = t
            default:
                throw CryptoError.paramError
            }
            return try CCRSACryptorDecrypt(privateKey: reference, padding: padding.rawValue, cipherText: data, tag: tag, digest: algorithm.rawValue)
        }
    }
    
    public struct PublicKey: CustomStringConvertible {
        public var description: String {
            "<RSA Public Key of \(size) bits>"
        }
        
        public typealias Components = (modulus: Data, exponent: Data)
        
        internal var reference: CCRSACryptorRef?
        
        /// The size of the key in bits.
        public var size: Int {
            CCRSAGetKeySize(reference)
        }
        /// The components of this key (modulus, exponent).
        public var components: Components {
            let components = try! CCRSAGetKeyComponents(key: reference)
            return (components.modulus, components.exponent)
        }
        
        /// The PKCS#1 formatted data of the key.
        public var PKCS1: Data {
            try! CCRSACryptorExport(key: reference)
        }
        /// The PEM encoded string of the key.
        public var PEM: String {
            return rsaPublicPEMHeader + PKCS1.base64EncodedString(options: .lineLength64Characters) + rsaPublicPEMFooter
        }
        
        internal init(reference: CCRSACryptorRef?) {
            self.reference = reference
        }
        
        /// Initialize an RSA public key.
        /// - Parameter pkcs1: The PKCS#1 formatted data.
        public init(pkcs1: Data) throws {
            try CCRSACryptorImport(keyPackage: pkcs1, key: &reference)
            guard CCRSAGetKeyType(reference) == .public else { throw CryptoError.invalidKey }
        }
        
        /// Initialize the key from its PEM format.
        /// - Parameter pem: The PEM encoded data.
        public init(pem: String) throws {
            let trimmed = pem.replacingOccurrences(of: rsaPublicPEMHeader, with: "").replacingOccurrences(of: rsaPublicPEMFooter, with: "")
            guard let der = Data(base64Encoded: trimmed, options: .ignoreUnknownCharacters) else {
                throw CryptoError.decodeError
            }
            try self.init(pkcs1: der)
        }
        
        /// Initialize the key from its components.
        /// - Parameters:
        ///   - modulus: The modulus.
        ///   - exponent: The exponent.
        public init(modulus: Data, exponent: Data) throws {
            try CCRSACryptorCreateFromData(type: .public, modulus: modulus, exponent: exponent, p: nil, q: nil, reference: &reference)
            guard CCRSAGetKeyType(reference) == .public else { throw CryptoError.invalidKey }
        }
        
        /// Verify the signature of signed data.
        /// - Parameters:
        ///   - signature: The signature.
        ///   - data: The signed data.
        ///   - padding: The signature padding scheme.
        public func verify(signature: Data, for data: Data, padding: Asymmetric.Padding) throws {
            var algorithm: Digest.Algorithm
            var saltSize: Int = 0
            switch padding {
            case .PKCS1(let a):
                algorithm = a
            case .PSS(let a, let s):
                algorithm = a
                saltSize = s
            default: throw CryptoError.paramError
            }
            try CCRSACryptorVerify(publicKey: reference, padding: padding.rawValue, data: data, signature: signature, digest: algorithm.rawValue, saltSize: saltSize)
        }
        
        /// Encrypt data.
        /// - Parameters:
        ///   - data: The data to encrypt.
        ///   - padding: The encryption padding scheme.
        /// - Returns: The encrypted data.
        public func encrypt(_ data: Data, padding: Asymmetric.Padding) throws -> Data {
            var algorithm: Digest.Algorithm
            var tag: Data? = nil
            switch padding {
            case .PKCS1(_):
                algorithm = .none
            case .OAEP(let a, let t):
                algorithm = a
                tag = t
            default:
                throw CryptoError.paramError
            }
            return try CCRSACryptorEncrypt(publicKey: reference, padding: padding.rawValue, plainText: data, tag: tag, digest: algorithm.rawValue)
        }
    }
    
}

fileprivate let rsaPrivatePEMHeader = "-----BEGIN RSA PRIVATE KEY-----\n"
fileprivate let rsaPrivatePEMFooter = "\n-----END RSA PRIVATE KEY-----"

fileprivate let rsaPublicPEMHeader = "-----BEGIN RSA PUBLIC KEY-----\n"
fileprivate let rsaPublicPEMFooter = "\n-----END RSA PUBLIC KEY-----"
