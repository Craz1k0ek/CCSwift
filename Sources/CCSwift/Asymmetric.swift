import CCWrapper
import Foundation

public enum Asymmetric {
    /// Paddings used in asymmetric cryptography.
    public enum Padding {
        /// PKCS#1 padding with a digest algorithm.
        case PKCS1(Digest.Algorithm = .none)
        /// OAEP padding with a digest algorithm and optional tag.
        case OAEP(Digest.Algorithm, Data? = nil)
        /// PSS padding with a digest algorithm and a salt size.
        case PSS(Digest.Algorithm, Int = 20)
        
        internal var rawValue: CCAsymmetricPadding {
            switch self {
            case .PKCS1(_):     return .pkcs1
            case .OAEP(_, _):   return .oaep
            case .PSS(_, _): 	return .pss
            }
        }
    }
}
