//
//  String+CryptoUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 3/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation

extension String {
    public var base64EncodedString: String? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.base64EncodedString
    }
    
    public var base64DecodedString: Data? {
        return Data(base64Encoded: self)
    }
    
    public var crc32: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.crc32
    }
    
    public var md5: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.md5
    }
    
    public var sha1: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.sha1
    }
    
    public var sha224: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.sha224
    }
    
    public var sha256: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.sha256
    }
    
    public var sha384: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.sha384
    }
    
    public var sha512: Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.sha512
    }
    
    public func hmacMD5(with key: String) -> Data? {
        guard let data = self.data(using: .utf8),
              let secret = key.data(using: .utf8) else { return nil }
        return data.hmacMD5(with: secret)
    }
    
    public func hmacSHA1(with key: String) -> Data? {
        guard let data = self.data(using: .utf8),
              let secret = key.data(using: .utf8) else { return nil }
        return data.hmacSHA1(with: secret)
    }
    
    public func hmacSHA224(with key: String) -> Data? {
        guard let data = self.data(using: .utf8),
              let secret = key.data(using: .utf8) else { return nil }
        return data.hmacSHA224(with: secret)
    }
    
    public func hmacSHA256(with key: String) -> Data? {
        guard let data = self.data(using: .utf8),
              let secret = key.data(using: .utf8) else { return nil }
        return data.hmacSHA256(with: secret)
    }
    
    public func hmacSHA384(with key: String) -> Data? {
        guard let data = self.data(using: .utf8),
              let secret = key.data(using: .utf8) else { return nil }
        return data.hmacSHA384(with: secret)
    }
    
    public func hmacSHA512(with key: String) -> Data? {
        guard let data = self.data(using: .utf8),
              let secret = key.data(using: .utf8) else { return nil }
        return data.hmacSHA512(with: secret)
    }
    
    public func aesEncrypt(with key: Data, iv: Data? = nil) -> Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.aesEncrypt(with: key, iv: iv)
    }
    
    public func rsaEncrypt(with pubKey: SecKey, algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256) -> Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.rsaEncrypt(with: pubKey, algorithm: algorithm)
    }
    
    public func rsaSign(with priKey: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Data? {
        guard let data = self.data(using: .utf8) else { return nil }
        return data.rsaSign(with: priKey, algorithm: algorithm)
    }
    
    public func rsaVerify(signature: Data, with pubKey: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Bool {
        guard let data = self.data(using: .utf8) else { return false }
        return data.rsaVerify(signature: signature, with: pubKey, algorithm: algorithm)
    }
}
