import CCWrapper
import Foundation

public extension Data {
    /// Generate secure random data.
    /// - Parameter size: The number of bytes to generate.
    /// - Returns: The generated random data.
    static func random(ofSize size: Int) -> Data {
        let ccRandomBytes = try! CCRandomGenerateBytes(count: size)         // CommonCrypto random
        
        var secRandomBytes = Data(repeating: 0, count: size)                // Security random
        _ = secRandomBytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
        }
        
        return ccRandomBytes ^ secRandomBytes                               // XOR to get the best entropy
    }
    
    /// Perform a constant time safe compare.
    /// - Parameters:
    ///   - lhs: The left hand side of the operation.
    ///   - rhs: The right hand side of the operation
    /// - Returns: Whether or not the two sides are equal.
    static func === (_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
    }
    
    /// Perform the XOR operation on two `Data` objects.
    /// - Parameters:
    ///   - lhs: The left hand side of the operation.
    ///   - rhs: The right hand side of the operation.
    /// - Returns: The xor'ed data.
    internal static func ^ (_ lhs: Data, _ rhs: Data) -> Data {
        precondition(lhs.count == rhs.count, "Cannot XOR data of unequal size.")
        return Data(zip(lhs, rhs).map { $0 ^ $1 })
    }
}
