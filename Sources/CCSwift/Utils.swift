import Foundation

public extension Data {
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
}
