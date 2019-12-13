//
//  Data+CryptoUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 3/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation
import CommonCrypto

extension Data {
    public var hex: String {
        let length = self.count
        return (0..<length).reduce("", { $0 + String(format: "%02hx", self[$1]) })
    }
    
    public var base64EncodedString: String {
        self.base64EncodedString()
    }
    
    public var crc32: Data {
        return CryptoUtil.crcData(data: self)
    }
    
    public var md5: Data {
        return CryptoUtil.hashData(data: self, algorithm: .MD5)
    }
    
    public var sha1: Data {
        return CryptoUtil.hashData(data: self, algorithm: .SHA1)
    }
    
    public var sha224: Data {
        return CryptoUtil.hashData(data: self, algorithm: .SHA224)
    }
    
    public var sha256: Data {
        return CryptoUtil.hashData(data: self, algorithm: .SHA256)
    }
    
    public var sha384: Data {
        return CryptoUtil.hashData(data: self, algorithm: .SHA384)
    }
    
    public var sha512: Data {
        return CryptoUtil.hashData(data: self, algorithm: .SHA512)
    }
    
    public func hmacMD5(with key: Data) -> Data {
        return CryptoUtil.hmacData(data: self, key: key, algorithm: .MD5)
    }
    
    public func hmacSHA1(with key: Data) -> Data {
        return CryptoUtil.hmacData(data: self, key: key, algorithm: .SHA1)
    }
    
    public func hmacSHA224(with key: Data) -> Data {
        return CryptoUtil.hmacData(data: self, key: key, algorithm: .SHA224)
    }
    
    public func hmacSHA256(with key: Data) -> Data {
        return CryptoUtil.hmacData(data: self, key: key, algorithm: .SHA256)
    }
    
    public func hmacSHA384(with key: Data) -> Data {
        return CryptoUtil.hmacData(data: self, key: key, algorithm: .SHA384)
    }
    
    public func hmacSHA512(with key: Data) -> Data {
        return CryptoUtil.hmacData(data: self, key: key, algorithm: .SHA512)
    }
    
    public func aesEncrypt(with key: Data, iv: Data? = nil) -> Data? {
        guard key.count == kCCKeySizeAES128 ||
              key.count == kCCKeySizeAES192 ||
              key.count == kCCKeySizeAES256
        else { return nil }
        let _iv: Data! = iv == nil ? Data(repeating: 0, count: 16) : iv!
        return CryptoUtil.aesData(CCOperation(kCCEncrypt), data: self, key: key, iv: _iv)
    }
    
    public func aesDecrypt(with key: Data, iv: Data? = nil) -> Data? {
        guard key.count == kCCKeySizeAES128 ||
              key.count == kCCKeySizeAES192 ||
              key.count == kCCKeySizeAES256
        else { return nil }
        let _iv: Data! = iv == nil ? Data(repeating: 0, count: 16) : iv!
        return CryptoUtil.aesData(CCOperation(kCCDecrypt), data: self, key: key, iv: _iv)
    }
    
    public func rsaEncrypt(with pubKey: SecKey, algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256) -> Data? {
        return CryptoUtil.rsaEncrypt(data: self, with: pubKey, algorithm: algorithm)
    }
    
    public func rsaDecrypt(with priKey: SecKey, algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256) -> Data? {
        return CryptoUtil.rsaDecrypt(data: self, with: priKey, algorithm: algorithm)
    }
    
    public func rsaSign(with priKey: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Data? {
        return CryptoUtil.rsaSign(data: self, with: priKey, algorithm: algorithm)
    }
    
    public func rsaVerify(data: Data, with pubKey: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Bool {
        return CryptoUtil.rsaVerify(data: data, signature: self, with: pubKey, algorithm: algorithm)
    }
    
    public func rsaVerify(msg: String, with pubKey: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Bool {
        guard let data = msg.data(using: .utf8) else { return false }
        return CryptoUtil.rsaVerify(data: data, signature: self, with: pubKey, algorithm: algorithm)
    }
    
    public func rsaVerify(signature: Data, with pubKey: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Bool {
        return CryptoUtil.rsaVerify(data: self, signature: signature, with: pubKey, algorithm: algorithm)
    }
}
