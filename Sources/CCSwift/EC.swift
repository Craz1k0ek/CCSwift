import CCWrapper
import Foundation

public enum EC {
    public struct PrivateKey: CustomStringConvertible {
        public var description: String {
            "<EC Private key of \(size) bits>"
        }
        
        public typealias Components = (x: Data, y: Data, d: Data)
        
        internal var reference: CCECCryptorRef?
        
        /// The size of the key in bits.
        public var size: Int {
            CCECGetKeySize(reference)
        }
        /// The components of the key (X, Y and D).
        public var components: Components {
            let components = try! CCECCryptorGetKeyComponents(key: reference)
            return (components.x, components.y, components.d!)
        }
        /// The public key of this private key.
        public var publicKey: EC.PublicKey {
            return EC.PublicKey(reference: CCECCryptorGetPublicKeyFromPrivateKey(privateKey: reference))
        }
        
        /// The X9.63 formatted data of the key using the uncompressed point.
        public var uncompressed: Data {
            try! CCECCryptorExportKey(format: .binary, key: reference)
        }
        
        /// Initialize an EC private key for given size.
        /// - Parameter size: The size of the key.
        public init(size: Int) throws {
            var publicRef: CCECCryptorRef?
            try CCECCryptorGeneratePair(keySize: size, publicKey: &publicRef, privateKey: &reference)
        }
        
        /// Initialize an EC private key from its uncompressed data.
        /// - Parameter uncompressed: The X9.63 uncompressed data.
        public init(uncompressed: Data) throws {
            try CCECCryptorImportKey(format: .binary, keyPackage: uncompressed, keyType: .private, key: &reference)
            guard CCECGetKeyType(reference) == .private else { throw CryptoError.invalidKey }
        }
        
        /// Sign data.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - digest: The digest algorithm used to hash the data.
        /// - Returns: The signature.
        public func sign(_ data: Data, digest: Digest.Algorithm) throws -> Data {
            try sign(hash: try CCDigest(algorithm: digest.rawValue, data: data))
        }
        
        /// Sign a hash.
        /// - Parameter hash: The hash to sign.
        /// - Returns: The signature.
        public func sign(hash: Data) throws -> Data {
            try CCECCryptorSignHash(privateKey: reference, hash: hash)
        }
        
        /// Perform Diffie-Hellman key exchange with a public key.
        /// - Parameters:
        ///   - publicKey: The public key.
        ///   - size: The expected size of the computed shared secret.
        /// - Returns: The computed shared secret.
        public func computeSharedSecret(for publicKey: EC.PublicKey, size: Int) throws -> Data {
            try CCECCryptorComputeSharedSecret(privateKey: reference, publicKey: publicKey.reference, size: size)
        }
    }
    
    public struct PublicKey: CustomStringConvertible {
        public var description: String {
            "<EC Public Key of \(size) bits>"
        }
        
        public typealias Components = (x: Data, y: Data)
        
        internal var reference: CCECCryptorRef?
        
        /// The size of the key in bits.
        public var size: Int {
            CCECGetKeySize(reference)
        }
        /// The components of this key (X and Y).
        public var components: Components {
            let components = try! CCECCryptorGetKeyComponents(key: reference)
            return (components.x, components.y)
        }
        
        /// The X9.63 formatted data of the key using the uncompressed point.
        public var uncompressed: Data {
            try! CCECCryptorExportKey(format: .binary, key: reference)
        }
        /// The X9.63 formatted data of the key using the compressed point.
        public var compressed: Data {
            try! CCECCryptorExportKey(format: .compact, key: reference)
        }
        
        internal init(reference: CCECCryptorRef?) {
            self.reference = reference
        }
        
        /// Initialize an EC public key.
        /// - Parameter uncompressed: The X9.63 formatted data of the key using the uncompressed point.
        public init(uncompressed: Data) throws {
            try CCECCryptorImportPublicKey(keyPackage: uncompressed, key: &reference)
            guard CCECGetKeyType(reference) == .public else { throw CryptoError.invalidKey }
        }
        
        /// Verify a signature for data with a specified digest algorithm.
        /// - Parameters:
        ///   - signature: The signature.
        ///   - data: The signed data.
        ///   - digest: The digest algorithm.
        public func verify(signature: Data, data: Data, digest: Digest.Algorithm) throws {
            try verify(signature: signature, hash: try CCDigest(algorithm: digest.rawValue, data: data))
        }
        
        /// Verify a signature for a hash.
        /// - Parameters:
        ///   - signature: The signature.
        ///   - hash: The signed hash.
        public func verify(signature: Data, hash: Data) throws {
            try CCECCryptorVerifyHash(publicKey: reference, hash: hash, signature: signature)
        }
    }
}
