import CCWrapper
import Foundation

internal protocol KDFunction {
    var parameters: CCKDFParametersRef? { get }
}

@available(iOS 13.0, macOS 10.15, *)
extension KDFunction {
    internal func derive(digest: Digest.Algorithm, key: Data, size: Int) throws -> Data {
        return try CCDeriveKey(parameters, digest: digest.rawValue, key: key, derivedSize: size)
    }
}

public struct PBKDF2: KDFunction {
    var parameters: CCKDFParametersRef?
    
    @available(iOS 13.0, macOS 10.15, *)
    internal init(rounds: UInt32, salt: Data) throws {
        try CCKDFParametersCreatePbkdf2(&parameters, rounds: rounds, salt: salt)
    }
    
    public static func derive(_ password: String, salt: Data, digest: Digest.Algorithm, rounds: UInt32 = 10_000, size: Int = 32) throws -> Data {
        if #available(iOS 13.0, macOS 10.15, *) {
            return try Self(rounds: rounds, salt: salt).derive(digest: digest, key: Data(password.utf8), size: size)
        } else {
            return try CCKeyDerivationPBKDF(algorithm: .pbkdf2, password: password, salt: salt, prf: prf(for: digest), rounds: rounds, derivedSize: size)
        }
    }
    
    fileprivate static func prf(for digest: Digest.Algorithm) throws -> CCPseudoRandomAlgorithm {
        switch digest {
        case .SHA1:     return .prfHmacSHA1
        case .SHA224:   return .prfHmacSHA224
        case .SHA256:   return .prfHmacSHA256
        case .SHA384:   return .prfHmacSHA384
        case .SHA512:   return .prfHmacSHA512
        default: throw CryptoError.unimplemented
        }
    }
}

@available(iOS 13.0, macOS 10.15, *)
public struct CTRHMAC: KDFunction {
    var parameters: CCKDFParametersRef?
    
    init(label: Data, context: Data) throws {
        try CCKDFParametersCreateCtrHmac(&parameters, label: label, context: context)
    }
    
    init(context: Data) throws {
        try CCKDFParametersCreateCtrHmacFixed(&parameters, context: context)
    }
    
    public static func derive(_ key: Data, label: Data, context: Data, digest: Digest.Algorithm, size: Int = 32) throws -> Data {
        return try Self(label: label, context: context).derive(digest: digest, key: key, size: size)
    }
    
    public static func derive(_ key: Data, context: Data, digest: Digest.Algorithm, size: Int = 32) throws -> Data {
        try Self(context: context).derive(digest: digest, key: key, size: size)
    }
}

public struct HKDF: KDFunction {
    var parameters: CCKDFParametersRef?
    
    @available(iOS 13.0, macOS 10.15, *)
    init(salt: Data, context: Data) throws {
        try CCKDFParametersCreateHkdf(&parameters, salt: salt, context: context)
    }
    
    public static func derive(_ key: Data, salt: Data?, info: Data, digest: Digest.Algorithm, size: Int = 32) throws -> Data {
        if #available(iOS 13.0, macOS 10.15, *) {
            return try Self(salt: salt ?? Data(repeating: 0, count: digest.digestSize), context: info).derive(digest: digest, key: key, size: size)
        } else {
            return try hkdf(key, salt: salt, info: info, digest: digest, size: size)
        }
    }
    
    @available(iOS, deprecated: 13.0)
    @available(macOS, deprecated: 10.15)
    fileprivate static func hkdf(_ ikm: Data, salt: Data?, info: Data, digest: Digest.Algorithm, size: Int) throws -> Data {
        let salt = salt ?? Data(repeating: 0, count: digest.digestSize)
        
        // Generate the PRK (extract)
        let prk = HMAC.mac(for: ikm, using: salt, digest: digest)
        
        // Prepare the OKM
        var mixin = Data()
        var derived = Data()
        
        // Perform the derivation (expand)
        for iteration in 0 ..< Int(ceil(Double(size) / Double(digest.digestSize))) {
            mixin.append(info)
            mixin.append(Data([1 + UInt8(iteration)]))
            mixin = HMAC.mac(for: mixin, using: prk, digest: digest)
            derived += mixin
        }
        
        return derived.subdata(in: 0 ..< size)
    }
}

public struct ANSIX963: KDFunction {
    var parameters: CCKDFParametersRef?
    
    @available(iOS 13.0, macOS 10.15, *)
    init(info: Data) throws {
        try CCKDFParametersCreateAnsiX963(&parameters, sharedInfo: info)
    }
    
    public static func derive(_ key: Data, info: Data, digest: Digest.Algorithm, size: Int = 32) throws -> Data {
        if #available(iOS 13.0, macOS 10.15, *) {
            print("Available")
            return try Self(info: info).derive(digest: digest, key: key, size: size)
        } else {
            return try ansix963(key, info: info, digest: digest, size: size)
        }
    }
    
    @available(iOS, deprecated: 13.0)
    @available(macOS, deprecated: 10.15)
    fileprivate static func ansix963(_ ikm: Data, info: Data, digest: Digest.Algorithm, size: Int) throws -> Data {
        var counter: UInt32 = 1
        var derived = Data()
        
        for _ in 0 ..< Int(ceil(Double(size) / Double(digest.digestSize))) + 1 {
            let hasher = try Digest(algorithm: digest)
            try hasher.update(ikm)
            try hasher.update(counter.bigEndian.bytes)
            try hasher.update(info)
            derived.append(try hasher.finalize())
            hasher.destroy()
            counter += 1
        }
        
        return derived.subdata(in: 0 ..< size)
    }
}

/// Extension used to extract the bigendian bytes of the counter.
fileprivate extension UInt32 {
    var bytes: Data {
        var copy = self
        return Data(bytes: &copy, count: MemoryLayout<Self>.size)
    }
}
