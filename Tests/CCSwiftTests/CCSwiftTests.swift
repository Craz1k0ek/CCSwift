import XCTest
import CCSwift

final class CCSwiftTests: XCTestCase {
    func testRSA() throws {
        let pk = try RSA.PrivateKey(size: 2048)
        let pub = pk.publicKey
        
        print(pk.PEM, "\n", pub.PEM)
        
        let message = Data("Hello World".utf8)
        
        let signature = try pk.sign(data: message, padding: .PSS(.SHA256, 30))
        print(signature as NSData)
        try pub.verify(signature: signature, for: message, padding: .PSS(.SHA256, 30))
        
        let ct = try pub.encrypt(Data("Hello World".utf8), padding: .OAEP(.SHA256))
        print(ct as NSData)
        let pt = try pk.decrypt(ct, padding: .OAEP(.SHA256))
        print(pt as NSData, String(data: pt, encoding: .utf8)!)
        
        print(pk, pub)
        print(pk.components, pub.components)
    }
    
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
