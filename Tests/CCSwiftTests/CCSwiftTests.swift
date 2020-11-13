import XCTest
import CCSwift

final class CCSwiftTests: XCTestCase {
    func testHashes() throws {
        let message = Data("abc".utf8)
        
        let md5 = try MD5.hash(message)
        let rmd = try RIPEMD160.hash(message)
        let sha1 = try SHA1.hash(message)
        let sha224 = try SHA224.hash(message)
        let sha256 = try SHA256.hash(message)
        let sha384 = try SHA384.hash(message)
        let sha512 = try SHA512.hash(message)
        
        print(md5 as NSData)
        print(rmd as NSData)
        print(sha1 as NSData)
        print(sha224 as NSData)
        print(sha256 as NSData)
        print(sha384 as NSData)
        print(sha512 as NSData)
    }
}
