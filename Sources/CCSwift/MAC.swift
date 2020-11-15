import CCWrapper
import Foundation

public struct HMAC {
    internal var reference: CCHmacContextRef
    
    /// The number of bytes this HMAC will produce.
    public var outputSize: Int {
        CCHmacOutputSizeFromRef(reference)
    }
    
    internal init(reference: CCHmacContextRef) {
        self.reference = reference
    }
    
    /// Initialize an HMAC context.
    /// - Parameters:
    ///   - key: The key used to MAC.
    ///   - digest: The digest algorithm.
    public init(key: Data, digest: Digest.Algorithm) {
        reference = CCHmacCreate(algorithm: digest.rawValue, key: key)
    }
    
    /// Create a clone of an initialized HMAC context.
    public func copy() -> Self {
        Self.init(reference: reference)
    }
    
    /// Process some data.
    /// - Parameter data: The data to process.
    public func update(_ data: Data) {
        CCHmacUpdate(reference, data: data)
    }
    
    /// Obtain the final Message Authentication Code.
    /// - Returns: The final MAC
    public func finalize() -> Data {
        CCHmacFinalize(reference)
    }
    
    /// Destroy the HMAC context.
    public func destroy() {
        CCHmacDestroy(reference)
    }
    
    /// Stateless, one-shot HMAC function.
    /// - Parameters:
    ///   - data: The data to MAC.
    ///   - key: The key used to MAC.
    ///   - digest: The digest algorithm.
    /// - Returns: The final MAC.
    public static func mac(for data: Data, using key: Data, digest: Digest.Algorithm) -> Data {
        CCHmacOneShot(algorithm: digest.rawValue, key: key, data: data)
    }
}

public struct CMAC {
    internal var reference: CCCmacContextRef
    
    /// The number of bytes this CMAC will produce.
    public var outputSize: Int {
        CCAESCmacOutputSizeFromContext(reference)
    }
    
    /// Initialize a CMAC context.
    /// - Parameter key: The key used to MAC.
    public init(key: Data) {
        reference = CCAESCmacCreate(key: key)
    }
    
    /// Process some data.
    /// - Parameter data: The data to process.
    public func update(_ data: Data) {
        CCAESCmacUpdate(reference, data: data)
    }
    
    /// Obtain the final Message Authentication Code.
    /// - Returns: The final MAC.
    public func finalize() -> Data {
        CCAESCmacFinalize(reference)
    }
    
    /// Destroy the CMAC context.
    public func destroy() {
        CCAESCmacDestroy(reference)
    }
    
    /// Stateless, one-shot CMAC function.
    /// - Parameters:
    ///   - data: The data to MAC.
    ///   - key: The key used to MAC.
    /// - Returns: The final MAC.
    public static func mac(for data: Data, using key: Data) -> Data {
        CCAESCmac(key: key, data: data)
    }
}
