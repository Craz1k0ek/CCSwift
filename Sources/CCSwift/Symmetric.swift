import CCWrapper
import Foundation

public enum Symmetric {
    public enum Padding {
        /// No padding.
        case none
        /// PKCS#7 padding.
        case PKCS7
        
        internal var rawValue: CCPadding {
            switch self {
            case .none:     return .none
            case .PKCS7:    return .pkcs7Padding
            }
        }
    }
    
    public enum Algorithm {
        /// Advanced Encryption Standard, 128-bit block.
        case AES
        /// Data Encryption Standard.
        case DES
        /// Triple-DES, three key, EDE configuration.
        case TripleDES
        /// CAST.
        case CAST
        /// RC4 stream cipher.
        case RC4
        /// RC2 block cipher.
        case RC2
        /// Blowfish block cipher.
        case Blowfish
        
        internal var rawValue: CCAlgorithm {
            switch self {
            case .AES:          return .aes
            case .DES:          return .des
            case .TripleDES:    return .tripleDES
            case .CAST:         return .cast
            case .RC4:          return .rc4
            case .RC2:          return .rc2
            case .Blowfish:     return .blowfish
            }
        }
        
        /// The block size of the algorithm.
        /// - Note: RC4 does not have a blocksize.
        public var blockSize: Int {
            switch self {
            case .AES:          return CCBlockSize.aes.rawValue
            case .DES:          return CCBlockSize.des.rawValue
            case .TripleDES:    return CCBlockSize.tripleDES.rawValue
            case .CAST:         return CCBlockSize.cast.rawValue
            case .RC2:          return CCBlockSize.rc2.rawValue
            case .Blowfish:     return CCBlockSize.blowfish.rawValue
            case .RC4:          fatalError("RC4 does not have a block size.")
            }
        }
        
        /// The default initialization vector for the algorithm.
        /// - Note: RC4 does not support this.
        public var nullIV: Data {
            switch self {
            case .AES:          return Data(repeating: 0, count: blockSize)
            case .DES:          return Data(repeating: 0, count: blockSize)
            case .TripleDES:    return Data(repeating: 0, count: blockSize)
            case .CAST:         return Data(repeating: 0, count: blockSize)
            case .RC2:          return Data(repeating: 0, count: blockSize)
            case .Blowfish:     return Data(repeating: 0, count: blockSize)
            case .RC4:          fatalError("RC4 does not support an initialization vector.")
            }
        }
    }
}
