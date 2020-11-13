import CCWrapper
import Foundation

public enum Digest {
    public enum Algorithm {
        /// No digest.
        case none
        /// MD5 digest.
        @available(iOS, deprecated: 13.0)
        @available(macOS, deprecated: 10.15)
        case md5
        /// RMD 160 bit digest.
        @available(iOS, deprecated: 13.0)
        @available(macOS, deprecated: 10.15)
        case rmd160
        /// SHA-1 digest.
        @available(iOS, deprecated: 13.0)
        @available(macOS, deprecated: 10.15)
        case sha1
        /// SHA-2 224 bit digest.
        case sha224
        /// SHA-2 256 bit digest.
        case sha256
        /// SHA-2 384 bit digest.
        case sha384
        /// SHA-2 512 bit digest.
        case sha512
        
        /// The block size of the algorithm.
        public var blockSize: Int {
            CCDigestGetBlockSize(rawValue)
        }
        
        /// The digest size of the algorithm.
        public var digestSize: Int {
            CCDigestGetOutputSize(rawValue)
        }
        
        internal var rawValue: CCDigestAlgorithm {
            switch self {
            case .none:     return .none
            case .md5:      return .md5
            case .rmd160:   return .rmd160
            case .sha1:     return .sha1
            case .sha224:   return .sha224
            case .sha256:   return .sha256
            case .sha384:   return .sha384
            case .sha512:   return .sha512
            }
        }
    }
}

public protocol DigestFunction {
    /// The algorithm of the digest function.
    static var algorithm: Digest.Algorithm { get }
    
    /// The reference of the digest function.
    var reference: CCDigestRef { get }
    
    /// Initialize the digest context.
    init() throws
}

public extension DigestFunction {
    /// Continue to digest data.
    /// - Parameter data: The data to digest.
    func update(_ data: Data) throws {
        try CCDigestUpdate(reference, data: data)
    }
    
    /// Conclude digest operations and produce the digest output.
    /// - Returns: The digest bytes.
    func finalize() throws -> Data {
        try CCDigestFinalize(reference)
    }
    
    /// Clear and free the digest context.
    func destroy() {
        CCDigestDestroy(reference)
    }
    
    /// Clear and re-initialize the digest context.
    func reset() {
        CCDigestReset(reference)
    }
    
    /// Stateless, one-shot digest function.
    /// - Parameter data: The data to digest.
    /// - Returns: The digest bytes.
    static func hash(_ data: Data) throws -> Data {
        let digestFunction = try Self()
        try digestFunction.update(data)
        let digest = try digestFunction.finalize()
        digestFunction.destroy()
        return digest
    }
}

@available(iOS, deprecated: 13.0)
@available(macOS, deprecated: 10.15)
public struct MD5: DigestFunction {
    public static let algorithm: Digest.Algorithm = .md5
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

@available(iOS, deprecated: 13.0)
@available(macOS, deprecated: 10.15)
public struct RIPEMD160: DigestFunction {
    public static let algorithm: Digest.Algorithm = .rmd160
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

/// SHA-1 digest.
@available(iOS, deprecated: 13.0)
@available(macOS, deprecated: 10.15)
public struct SHA1: DigestFunction {
    public static let algorithm: Digest.Algorithm = .sha1
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

/// SHA-2 224 bit digest.
public struct SHA224: DigestFunction {
    public static let algorithm: Digest.Algorithm = .sha224
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

/// SHA-2 256 bit digest.
public struct SHA256: DigestFunction {
    public static let algorithm: Digest.Algorithm = .sha256
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

/// SHA-2 384 bit digest.
public struct SHA384: DigestFunction {
    public static let algorithm: Digest.Algorithm = .sha384
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

/// SHA-2 512 bit digest.
public struct SHA512: DigestFunction {
    public static let algorithm: Digest.Algorithm = .sha512
    
    public var reference: CCDigestRef
    
    public init() throws {
        reference = CCDigestCreate(algorithm: Self.algorithm.rawValue)
        try CCDigestInit(algorithm: Self.algorithm.rawValue, reference: reference)
    }
}

