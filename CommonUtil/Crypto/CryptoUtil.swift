//
//  CrytoUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 3/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation
import CommonCrypto
import zlib


protocol FileHasher {
    func updateHasher(data: Data)
    func finalHasher() -> Data
}


public enum HashAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    var hmacAlgotirhm: CCHmacAlgorithm {
        switch self {
            case    .MD5: return CCHmacAlgorithm(kCCHmacAlgMD5)
            case   .SHA1: return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case .SHA224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
            case .SHA256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case .SHA384: return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case .SHA512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
        }
    }
    
    var digestBuffer: [UInt8] {
        switch self {
            case    .MD5: return [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            case   .SHA1: return [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            case .SHA224: return [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            case .SHA256: return [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            case .SHA384: return [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
            case .SHA512: return [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        }
    }
    
    var fileHasher: FileHasher {
        switch self {
            case    .MD5: return MD5FileHasher()
            case   .SHA1: return SHA1FileHasher()
            case .SHA224: return SHA224FileHasher()
            case .SHA256: return SHA256FileHasher()
            case .SHA384: return SHA384FileHasher()
            case .SHA512: return SHA512FileHasher()
        }
    }
}


fileprivate class MD5FileHasher: FileHasher {
    var context = CC_MD5_CTX()
    
    init() { CC_MD5_Init(&context) }
    
    func updateHasher(data: Data) {
        data.withUnsafeBytes { dataByte -> Void in
            CC_MD5_Update(&context, dataByte.baseAddress!, numericCast(data.count))
        }
    }
    
    func finalHasher() -> Data {
        var digest = HashAlgorithm.MD5.digestBuffer
        CC_MD5_Final(&digest, &context)
        return Data(digest)
    }
}


fileprivate class SHA1FileHasher: FileHasher {
    var context = CC_SHA1_CTX()
    
    init() { CC_SHA1_Init(&context) }
    
    func updateHasher(data: Data) {
        data.withUnsafeBytes { dataByte -> Void in
            CC_SHA1_Update(&context, dataByte.baseAddress!, numericCast(data.count))
        }
    }
    
    func finalHasher() -> Data {
        var digest = HashAlgorithm.SHA1.digestBuffer
        CC_SHA1_Final(&digest, &context)
        return Data(digest)
    }
}

fileprivate class SHA224FileHasher: FileHasher {
    var context = CC_SHA256_CTX()
    
    init() { CC_SHA224_Init(&context) }
    
    func updateHasher(data: Data) {
        data.withUnsafeBytes { dataByte -> Void in
            CC_SHA224_Update(&context, dataByte.baseAddress!, numericCast(data.count))
        }
    }
    
    func finalHasher() -> Data {
        var digest = HashAlgorithm.SHA224.digestBuffer
        CC_SHA224_Final(&digest, &context)
        return Data(digest)
    }
}

fileprivate class SHA256FileHasher: FileHasher {
    var context = CC_SHA256_CTX()
    
    init() { CC_SHA256_Init(&context) }
    
    func updateHasher(data: Data) {
        data.withUnsafeBytes { dataByte -> Void in
            CC_SHA256_Update(&context, dataByte.baseAddress!, numericCast(data.count))
        }
    }
    
    func finalHasher() -> Data {
        var digest = HashAlgorithm.SHA256.digestBuffer
        CC_SHA256_Final(&digest, &context)
        return Data(digest)
    }
}

fileprivate class SHA384FileHasher: FileHasher {
    var context = CC_SHA512_CTX()
    
    init() { CC_SHA384_Init(&context) }
    
    func updateHasher(data: Data) {
        data.withUnsafeBytes { dataByte -> Void in
            CC_SHA384_Update(&context, dataByte.baseAddress!, numericCast(data.count))
        }
    }
    
    func finalHasher() -> Data {
        var digest = HashAlgorithm.SHA384.digestBuffer
        CC_SHA384_Final(&digest, &context)
        return Data(digest)
    }
}


fileprivate class SHA512FileHasher: FileHasher {
    var context = CC_SHA512_CTX()
    
    init() { CC_SHA512_Init(&context) }
    
    func updateHasher(data: Data) {
        data.withUnsafeBytes { dataByte -> Void in
            CC_SHA512_Update(&context, dataByte.baseAddress!, numericCast(data.count))
        }
    }
    
    func finalHasher() -> Data {
        var digest = HashAlgorithm.SHA512.digestBuffer
        CC_SHA512_Final(&digest, &context)
        return Data(digest)
    }
}

public class CryptoUtil {
    private static let bufferSize = 5242880 // 5MB
    
    public static func crcData(data: Data) -> Data {
        var result = Data(count: 4)
        var input = Array(data)
        let crcValue = crc32(0, &input, UInt32(data.count))
        result[0] = UInt8(crcValue >> 24)
        result[1] = UInt8((crcValue >> 16) & 0xff)
        result[2] = UInt8((crcValue >> 8)  & 0xff)
        result[3] = UInt8(crcValue & 0xff)
        return result
    }
    
    public static func hashData(data: Data, algorithm: HashAlgorithm) -> Data {
        var digest = algorithm.digestBuffer
        
        data.withUnsafeBytes({ dataBytes in
            switch algorithm {
                case    .MD5: CC_MD5(dataBytes.baseAddress!, CC_LONG(data.count), &digest)
                case   .SHA1: CC_SHA1(dataBytes.baseAddress!, CC_LONG(data.count), &digest)
                case .SHA224: CC_SHA224(dataBytes.baseAddress!, CC_LONG(data.count), &digest)
                case .SHA256: CC_SHA256(dataBytes.baseAddress!, CC_LONG(data.count), &digest)
                case .SHA384: CC_SHA384(dataBytes.baseAddress!, CC_LONG(data.count), &digest)
                case .SHA512: CC_SHA512(dataBytes.baseAddress!, CC_LONG(data.count), &digest)
            }
        })
        
        return Data(digest)
    }
    
    public static func hashFile(url: URL, algorithm: HashAlgorithm) -> Data? {
        guard let file = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { file.closeFile() }
        let fileHasher = algorithm.fileHasher

        while autoreleasepool(invoking: {
            let data = file.readData(ofLength: bufferSize)
            if data.count > 0 {
                fileHasher.updateHasher(data: data)
                return true
            } else {
                return false
            }
        }) { }
            
        return fileHasher.finalHasher()
    }
    
    public static func hmacData(data: Data, key: Data, algorithm: HashAlgorithm) -> Data {
        var digest = algorithm.digestBuffer
        
        data.withUnsafeBytes({ dataBytes in
            key.withUnsafeBytes({ keyBytes in
                CCHmac(algorithm.hmacAlgotirhm, keyBytes.baseAddress!, key.count, dataBytes.baseAddress!, data.count, &digest)
            })
        })
        
        return Data(digest)
    }
    
    public static func hmacFile(url: URL, key: Data, algorithm: HashAlgorithm) -> Data? {
        guard let file = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { file.closeFile() }
        
        var context = CCHmacContext()
        key.withUnsafeBytes({ keyBytes in
            CCHmacInit(&context, algorithm.hmacAlgotirhm, keyBytes.baseAddress!, key.count)
        })
        
        while autoreleasepool(invoking: {
            let data = file.readData(ofLength: bufferSize)
            if data.count > 0 {
                data.withUnsafeBytes { dataByte -> Void in
                    CCHmacUpdate(&context, dataByte.baseAddress!, numericCast(data.count))
                }
                return true
            } else {
                return false
            }
        }) { }
            
        var digest = algorithm.digestBuffer
        CCHmacFinal(&context, &digest)
        return Data(digest)
    }
    
    public static func aesData(_ opertion: CCOperation, data: Data, key: Data, iv: Data) -> Data? {
        var resultLength = 0
        var result = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var status = CCCryptorStatus(kCCSuccess)
        
        data.withUnsafeBytes({ dataByte -> Void in
            key.withUnsafeBytes({ keyByte -> Void in
                iv.withUnsafeBytes({ ivByte -> Void in
                    status = CCCrypt(opertion, CCAlgorithm(kCCAlgorithmAES128), CCOperation(kCCOptionPKCS7Padding),
                                     keyByte.baseAddress!, key.count, ivByte.baseAddress!,
                                     dataByte.baseAddress!, data.count,
                                     &result, result.count, &resultLength)
                })
            })
        })
        
        if status == kCCSuccess { return Data(bytes: result, count: resultLength) }
        else { return nil }
    }
    
    public static func aesFile(_ opertion: CCOperation, src: URL, dst: URL, key: Data, iv: Data) -> Bool {
        guard let srcFile = InputStream(url: src),
              let dstFile = OutputStream(url: dst, append: false)
        else { return false }
        
        srcFile.open()
        dstFile.open()
        
        var cryptorRef: CCCryptorRef!
        var status = CCCryptorStatus(kCCSuccess)
        
        defer {
            srcFile.close()
            dstFile.close()
            CCCryptorRelease(cryptorRef)
        }

        key.withUnsafeBytes({ keyByte -> Void in
            iv.withUnsafeBytes({ ivByte -> Void in
                status = CCCryptorCreateWithMode(opertion, CCMode(kCCModeCBC), CCAlgorithm(kCCAlgorithmAES), CCOperation(kCCOptionPKCS7Padding),
                                                 ivByte.baseAddress!, keyByte.baseAddress!, key.count,
                                                 nil, 0, 0, 0, &cryptorRef)
            })
        })
        guard status == kCCSuccess else { return false }
        
        let resultSize = CCCryptorGetOutputLength(cryptorRef, bufferSize, true)
        var result = [UInt8](repeating: 0, count: resultSize)
        var resultLength = 0
        var bytesTotal = 0
        
        var fileContentBuffer = [UInt8](repeating: 0, count: bufferSize)

        while true {
            let fileBufferSize = srcFile.read(&fileContentBuffer, maxLength: bufferSize)
            guard fileBufferSize > 0 else {
                status = CCCryptorFinal(cryptorRef, &result, resultSize, &resultLength)
                if status != kCCSuccess { return false }
                dstFile.write(&result, maxLength: resultLength)
                break
            }

            key.withUnsafeBytes({ keyByte in
                iv.withUnsafeBytes({ ivByte in
                    status = CCCryptorUpdate(cryptorRef, fileContentBuffer, fileBufferSize, &result, resultSize, &resultLength)
                })
            })
            
            guard status == kCCSuccess else { return false }
            bytesTotal += resultLength
            dstFile.write(&result, maxLength: resultLength)
        }

        return true
    }
    
    public static func getRSAKeyPair(size: Int = 1024) -> (SecKey, SecKey)? {
        return RSA.getKeyPair(size: size)
    }
    
    public static func savePublicKey(_ key: SecKey, to url: URL) -> Bool {
        return RSA.savePublicKey(key, to: url)
    }
    
    public static func savePrivateKey(_ key: SecKey, to url: URL) -> Bool {
        return RSA.savePrivateKey(key, to: url)
    }
    
    public static func readRSAPublicKey(from url: URL) -> SecKey? {
        return RSA.readPublicKey(from: url)
    }
    
    public static func readRSAPrivateKey(from url: URL) -> SecKey? {
        return RSA.readPrivateKey(from: url)
    }
    
    public static func rsaEncrypt(data: Data, with pubKey: SecKey, algorithm: SecKeyAlgorithm) -> Data? {
        return RSA.encrypt(data: data, pubKey: pubKey, algorithm: algorithm)
    }
    
    public static func rsaDecrypt(data: Data, with priKey: SecKey, algorithm: SecKeyAlgorithm) -> Data? {
        return RSA.decrypt(data: data, priKey: priKey, algorithm: algorithm)
    }
    
    public static func rsaSign(data: Data, with priKey: SecKey, algorithm: SecKeyAlgorithm) -> Data? {
        return RSA.sign(data: data, priKey: priKey, algorithm: algorithm)
    }
    
    public static func rsaVerify(data: Data, signature: Data, with pubKey: SecKey, algorithm: SecKeyAlgorithm) -> Bool {
        return RSA.verify(data: data, signature: signature, pubKey: pubKey, algorithm: algorithm)
    }
}


fileprivate class RSA {
    static func getKeyPair(size: Int) -> (SecKey, SecKey)? {
        var publicKey: SecKey!
        var privateKey: SecKey!
        
        let rsaKeyPar = [kSecAttrType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: size] as CFDictionary
        let status = SecKeyGeneratePair(rsaKeyPar, &publicKey, &privateKey)
        return status == errSecSuccess ? (publicKey, privateKey) : nil
    }
    
    private static func saveKey(_ key: SecKey, to url: URL, type: String) -> Bool {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(key, &error) else { return false }
        var keyStr = "-----BEGIN \(type) KEY-----\n"
        keyStr += (keyData as Data).base64EncodedString(options: .lineLength76Characters)
        keyStr += "\n-----END \(type) KEY-----\n"
        do {
            try keyStr.write(to: url, atomically: true, encoding: .utf8)
        } catch { return false }
        return true
    }
    
    static func savePublicKey(_ key: SecKey, to url: URL) -> Bool {
        return saveKey(key, to: url, type: "PUBLIC")
    }
    
    static func savePrivateKey(_ key: SecKey, to url: URL) -> Bool {
        return saveKey(key, to: url, type: "PRIVATE")
    }
    
    static func readKey(from url: URL, isPrivte: Bool) -> SecKey? {
        guard var keyStr = try? String(contentsOf: url) else { return nil }
        keyStr = keyStr.replace(regex: "-----(BEGIN|END) (RSA )*[A-Z]+ KEY-----\n", with: "")
                       .replace(regex: "[\r\n]", with: "")
        let keyData = keyStr.base64DecodedString!
        let attributes = [
            kSecAttrKeyClass: isPrivte ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
        ] as CFDictionary
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(keyData as CFData, attributes, &error)
        return key
    }
    
    static func readPublicKey(from url: URL) -> SecKey? {
        return readKey(from: url, isPrivte: false)
    }
    
    static func readPrivateKey(from url: URL) -> SecKey? {
        return readKey(from: url, isPrivte: true)
    }
    
    static func encrypt(data: Data, pubKey: SecKey, algorithm: SecKeyAlgorithm) -> Data? {
        let blockSzie = SecKeyGetBlockSize(pubKey)
        guard blockSzie > data.count else { return nil }
        
        var error: Unmanaged<CFError>?
        let ciphertext = SecKeyCreateEncryptedData(pubKey, algorithm, data as CFData, &error)
        if let ciphertext = ciphertext {
            return ciphertext as Data
        }
        return nil
    }
    
    static func decrypt(data: Data, priKey: SecKey, algorithm: SecKeyAlgorithm) -> Data? {
        var error: Unmanaged<CFError>?
        let plaintext = SecKeyCreateDecryptedData(priKey, algorithm, data as CFData, &error)
        if let plaintext = plaintext {
            return plaintext as Data
        }
        return nil
    }
    
    static func sign(data: Data, priKey: SecKey, algorithm: SecKeyAlgorithm) -> Data? {
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(priKey, algorithm, data as CFData, &error)
        if let signature = signature {
            return signature as Data
        }
        return nil
    }
    
    static func verify(data: Data, signature: Data, pubKey: SecKey, algorithm: SecKeyAlgorithm) -> Bool {
        var error: Unmanaged<CFError>?
        let validate = SecKeyVerifySignature(pubKey, algorithm, data as CFData, signature as CFData, &error)
        return validate
    }
}
