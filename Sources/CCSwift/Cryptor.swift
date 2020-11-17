import CCWrapper
import Foundation

public final class RC4 {
    public static let algorithm: Symmetric.Algorithm = .RC4
    
    public final class Cryptor {
        /// The cryptor reference.
        internal var cryptor: CCCryptorRef?
        
        internal init(key: Data, operation: CCOperation, algorithm: Symmetric.Algorithm) throws {
            try CCCryptorCreateWithMode(op: operation, mode: .rc4, alg: algorithm.rawValue, padding: .none, iv: nil, key: key, tweak: nil, reference: &cryptor)
        }
        
        public final func update(_ data: Data) throws -> Data {
            try CCCryptorUpdate(cryptor, data: data)
        }
        
        public final func finalize() throws {
            _ = try CCCryptorFinalize(cryptor)
        }
        
        public final func release() throws {
            try CCCryptorRelease(cryptor)
        }
    }
    
    /// The key.
    internal let key: Data
    
    public init(key: Data) {
        self.key = key
    }
    
    public static func encrypt(_ data: Data, using key: Data) throws -> Data {
        let e = try Self(key: key).makeEncryptor()
        defer { try! e.release() }
        let ct = try e.update(data)
        try e.finalize()
        return ct
    }
    
    public static func decrypt(_ data: Data, using key: Data) throws -> Data {
        let d = try Self(key: key).makeDecryptor()
        defer { try! d.release() }
        let pt = try d.update(data)
        try d.finalize()
        return pt
    }
    
    public final func makeEncryptor() throws -> RC4.Cryptor {
        try RC4.Cryptor(key: key, operation: .encrypt, algorithm: .RC4)
    }
    
    public final func makeDecryptor() throws -> RC4.Cryptor {
        try RC4.Cryptor(key: key, operation: .decrypt, algorithm: .RC4)
    }
}

public class BlockCipherSuite {
    public typealias Cryptor = BlockCipherSuite._Cryptor
    public class var algorithm: Symmetric.Algorithm { .AES }
    
    public class _Cryptor {
        /// The cryptor reference.
        internal var cryptor: CCCryptorRef?
        
        internal init(key: Data, iv: Data?, padding: Symmetric.Padding, operation: CCOperation, mode: CCMode, algorithm: Symmetric.Algorithm) throws {
            try CCCryptorCreateWithMode(op: operation, mode: mode, alg: algorithm.rawValue, padding: padding.rawValue, iv: iv, key: key, tweak: nil, reference: &cryptor)
        }
        
        public final func update(_ data: Data) throws -> Data {
            try CCCryptorUpdate(cryptor, data: data)
        }
        
        public final func finalize() throws -> Data {
            try CCCryptorFinalize(cryptor)
        }
        
        public final func release() throws {
            try CCCryptorRelease(cryptor)
        }
    }
    
    /// The key.
    internal let key: Data
    internal let iv: Data?
    internal let padding: Symmetric.Padding
    internal let mode: CCMode
    
    required internal init(key: Data, iv: Data?, padding: Symmetric.Padding, mode: CCMode) {
        self.key = key
        self.iv = iv
        self.padding = padding
        self.mode = mode
    }
    
    public final func encrypt(_ data: Data) throws -> Data {
        let e = try makeEncryptor()
        let ct = try e.update(data) + e.finalize()
        try e.release()
        return ct
    }
    
    public final func decrypt(_ data: Data) throws -> Data {
        let d = try makeDecryptor()
        let pt = try d.update(data) + d.finalize()
        try d.release()
        return pt
    }
    
    public static func ECB(key: Data, padding: Symmetric.Padding = .none) -> Self {
        Self.init(key: key, iv: nil, padding: padding, mode: .ecb)
    }
    
    public static func CBC(key: Data, iv: Data, padding: Symmetric.Padding = .none) -> Self {
        Self.init(key: key, iv: iv, padding: padding, mode: .cbc)
    }
    
    public static func CFB(key: Data, iv: Data) -> Self {
        Self.init(key: key, iv: iv, padding: .none, mode: .cfb)
    }
    
    public static func CFB8(key: Data, iv: Data) -> Self {
        Self.init(key: key, iv: iv, padding: .none, mode: .cfb8)
    }
    
    public static func CTR(key: Data, iv: Data) -> Self {
        Self.init(key: key, iv: iv, padding: .none, mode: .ctr)
    }
    
    public static func OFB(key: Data, iv: Data) -> Self {
        Self.init(key: key, iv: iv, padding: .none, mode: .ofb)
    }
    
    public final func makeEncryptor() throws -> Cryptor {
        try Self.Cryptor.init(key: key, iv: iv, padding: padding, operation: .encrypt, mode: mode, algorithm: Self.algorithm)
    }
    
    public final func makeDecryptor() throws -> Cryptor {
        try Self.Cryptor.init(key: key, iv: iv, padding: padding, operation: .decrypt, mode: mode, algorithm: Self.algorithm)
    }
}

public final class DES: BlockCipherSuite {
    public override class var algorithm: Symmetric.Algorithm { .DES }
}

public final class TripleDES: BlockCipherSuite {
    public override class var algorithm: Symmetric.Algorithm { .TripleDES }
}

public final class CAST: BlockCipherSuite {
    public override class var algorithm: Symmetric.Algorithm { .CAST }
}

public final class RC2: BlockCipherSuite {
    public override class var algorithm: Symmetric.Algorithm { .RC2 }
}

public final class Blowfish: BlockCipherSuite {
    public override class var algorithm: Symmetric.Algorithm { .Blowfish }
}

public final class AES: BlockCipherSuite {
    public override class var algorithm: Symmetric.Algorithm { .AES }
    
    public static func GCM(key: Data, iv: Data, aad: Data) -> AESGCM {
        AESGCM(key: key, iv: iv, aad: aad)
    }
    
    public static func CCM(key: Data, iv: Data, aad: Data) -> AESCCM {
        AESCCM(key: key, iv: iv, aad: aad)
    }
}

public final class AESGCM {
    public typealias Cryptor = AESGCM._GCMCryptor
    
    public final class _GCMCryptor {
        /// The cryptor reference.
        internal var cryptor: CCCryptorRef?
        
        internal var operation: CCOperation
        internal var tag: Data
        
        internal init(key: Data, iv: Data, aad: Data) throws {
            try CCCryptorCreateWithMode(op: .encrypt, mode: .gcm, alg: .aes, padding: .none, iv: iv, key: key, tweak: nil, reference: &cryptor)
            try CCCryptorAddParameter(cryptor, parameter: .iv, data: iv)
            try CCCryptorAddParameter(cryptor, parameter: .authenticationData, data: aad)
            self.tag = Data(repeating: 0, count: Symmetric.Algorithm.AES.blockSize)
            self.operation = .encrypt
        }
        
        internal init(key: Data, iv: Data, aad: Data, tag: Data) throws {
            try CCCryptorCreateWithMode(op: .decrypt, mode: .gcm, alg: .aes, padding: .none, iv: iv, key: key, tweak: nil, reference: &cryptor)
            try CCCryptorAddParameter(cryptor, parameter: .iv, data: iv)
            try CCCryptorAddParameter(cryptor, parameter: .authenticationData, data: aad)
            self.tag = tag
            self.operation = .decrypt
        }
        
        public final func update(_ data: Data) throws -> Data {
            try CCCryptorUpdate(cryptor, data: data)
        }
        
        public final func finalize() throws -> Data {
            try CCCryptorGCMFinalize(cryptor, tag: &tag)
            return operation == .encrypt ? tag : Data()
        }
        
        public final func release() throws {
            try CCCryptorRelease(cryptor)
        }
    }
    
    /// The key.
    internal let key: Data
    internal let iv: Data
    internal let aad: Data
    
    internal init(key: Data, iv: Data, aad: Data) {
        self.key = key
        self.iv = iv
        self.aad = aad
    }
    
    public final func encrypt(_ data: Data) throws -> Data {
        let e = try makeEncryptor()
        let ct = try e.update(data) + e.finalize()
        try e.release()
        return ct
    }
    
    public final func decrypt(_ data: Data, tag: Data) throws -> Data {
        let d = try makeDecryptor(tag: tag)
        let pt = try d.update(data) + d.finalize()
        try d.release()
        return pt
    }
    
    public final func makeEncryptor() throws -> AESGCM.Cryptor {
        try Self.Cryptor.init(key: key, iv: iv, aad: aad)
    }
    
    public final func makeDecryptor(tag: Data) throws -> AESGCM.Cryptor {
        try Self.Cryptor.init(key: key, iv: iv, aad: aad, tag: tag)
    }
}

public final class AESCCM {
    public typealias Cryptor = AESCCM._CCMCryptor
    
    public final class _CCMCryptor {
        /// The cryptor reference.
        internal var cryptor: CCCryptorRef?
        
        internal var operation: CCOperation
        internal var mac: Data
        internal var macSize: Int
        
        internal init(key: Data, iv: Data, aad: Data, size: Int, macSize: Int) throws {
            try CCCryptorCreateWithMode(op: .encrypt, mode: .ccm, alg: .aes, padding: .none, iv: iv, key: key, tweak: nil, reference: &cryptor)
            try CCCryptorAddParameter(cryptor, parameter: .iv, data: iv)
            try CCCryptorAddParameter(cryptor, parameter: .dataSize, size: size)
            try CCCryptorAddParameter(cryptor, parameter: .macSize, size: macSize)
            try CCCryptorAddParameter(cryptor, parameter: .authenticationData, data: aad)
            self.mac = Data(repeating: 0, count: macSize)
            self.macSize = macSize
            self.operation = .encrypt
        }
        
        internal init(key: Data, iv: Data, aad: Data, size: Int, macSize: Int, mac: Data) throws {
            try CCCryptorCreateWithMode(op: .decrypt, mode: .ccm, alg: .aes, padding: .none, iv: iv, key: key, tweak: nil, reference: &cryptor)
            try CCCryptorAddParameter(cryptor, parameter: .iv, data: iv)
            try CCCryptorAddParameter(cryptor, parameter: .dataSize, size: size)
            try CCCryptorAddParameter(cryptor, parameter: .macSize, size: macSize)
            try CCCryptorAddParameter(cryptor, parameter: .authenticationData, data: aad)
            self.mac = mac
            self.macSize = macSize
            self.operation = .decrypt
        }
        
        public final func update(_ data: Data) throws -> Data {
            try CCCryptorUpdate(cryptor, data: data)
        }
        
        public final func finalize() throws -> Data {
            _ = try CCCryptorFinalize(cryptor)
            let mac = try CCCryptorGetParameter(cryptor, parameter: .authenticationTag, size: macSize)
            
            if operation == .decrypt {
                guard self.mac === mac else { throw CryptoError.unspecifiedError }
            }
            
            return operation == .encrypt ? mac : Data()
        }
        
        public final func release() throws {
            try CCCryptorRelease(cryptor)
        }
    }
    
    internal let key: Data
    internal let iv: Data
    internal let aad: Data
    
    internal init(key: Data, iv: Data, aad: Data) {
        self.key = key
        self.iv = iv
        self.aad = aad
    }
    
    public final func encrypt(_ data: Data, macSize: Int) throws -> Data {
        let e = try makeEncryptor(size: data.count, macSize: macSize)
        let ct = try e.update(data) + e.finalize()
        try e.release()
        return ct
    }
    
    public final func decrypt(_ data: Data, mac: Data) throws -> Data {
        let d = try makeDecryptor(size: data.count, macSize: mac.count, mac: mac)
        let pt = try d.update(data) + d.finalize()
        try d.release()
        return pt
    }
    
    public final func makeEncryptor(size: Int, macSize: Int) throws -> AESCCM.Cryptor {
        try Self.Cryptor.init(key: key, iv: iv, aad: aad, size: size, macSize: macSize)
    }
    
    public final func makeDecryptor(size: Int, macSize: Int, mac: Data) throws -> AESCCM.Cryptor {
        try Self.Cryptor.init(key: key, iv: iv, aad: aad, size: size, macSize: macSize, mac: mac)
    }
}
