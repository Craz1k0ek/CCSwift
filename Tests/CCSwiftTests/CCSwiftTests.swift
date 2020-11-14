import XCTest
import CCSwift

final class CCSwiftTests: XCTestCase {
    func testEC() throws {
        let pk = try EC.PrivateKey(size: 256)
        let pub = pk.publicKey
        print(pk, pub)
        
        let message = Data("Hello World".utf8)
        let digest = try SHA256.hash(message)
        
        let sraw = try pk.sign(message, digest: .SHA256)
        let sdig = try pk.sign(hash: digest)
        
        print(sraw as NSData, sdig as NSData)
        
        try pub.verify(signature: sraw, hash: digest)
        try pub.verify(signature: sdig, data: message, digest: .SHA256)
        
        let bob = try EC.PrivateKey(size: 256)
        
        let shared = try pk.computeSharedSecret(for: bob.publicKey, size: 32)
        let bobShared = try bob.computeSharedSecret(for: pub, size: 32)
        
        print(shared as NSData, bobShared as NSData)
    }
    
    func testRSA() throws {
        let pk = try RSA.PrivateKey(size: 2048)
        let pub = pk.publicKey
        
        print(pk.PEM, "\n", pub.PEM)
        
        let message = Data("Hello World".utf8)
        
        let signature = try pk.sign(message, padding: .PSS(.SHA256, 30))
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
