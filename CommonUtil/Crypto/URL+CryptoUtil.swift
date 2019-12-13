//
//  URL_CryptoUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 3/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation
import CommonCrypto

extension URL {
    public var md5: Data? {
        return CryptoUtil.hashFile(url: self, algorithm: .MD5)
    }

    public var sha1: Data? {
        return CryptoUtil.hashFile(url: self, algorithm: .SHA1)
    }

    public var sha224: Data? {
        return CryptoUtil.hashFile(url: self, algorithm: .SHA224)
    }

    public var sha256: Data? {
        return CryptoUtil.hashFile(url: self, algorithm: .SHA256)
    }

    public var sha384: Data? {
        return CryptoUtil.hashFile(url: self, algorithm: .SHA384)
    }

    public var sha512: Data? {
        return CryptoUtil.hashFile(url: self, algorithm: .SHA512)
    }

    public func hmacMD5(key: String) -> Data? {
        guard let secret = key.data(using: .utf8) else { return nil }
        return CryptoUtil.hmacFile(url: self, key: secret, algorithm: .MD5)
    }

    public func hmacSHA1(key: String) -> Data? {
        guard let secret = key.data(using: .utf8) else { return nil }
        return CryptoUtil.hmacFile(url: self, key: secret, algorithm: .SHA1)
    }

    public func hmacSHA224(key: String) -> Data? {
        guard let secret = key.data(using: .utf8) else { return nil }
        return CryptoUtil.hmacFile(url: self, key: secret, algorithm: .SHA224)
    }

    public func hmacSHA256(key: String) -> Data? {
        guard let secret = key.data(using: .utf8) else { return nil }
        return CryptoUtil.hmacFile(url: self, key: secret, algorithm: .SHA256)
    }

    public func hmacSHA384(key: String) -> Data? {
        guard let secret = key.data(using: .utf8) else { return nil }
        return CryptoUtil.hmacFile(url: self, key: secret, algorithm: .SHA384)
    }

    public func hmacSHA512(key: String) -> Data? {
        guard let secret = key.data(using: .utf8) else { return nil }
        return CryptoUtil.hmacFile(url: self, key: secret, algorithm: .SHA512)
    }
    
    public func aesEncrypt(dst: URL, key: Data, iv: Data? = nil) -> Bool {
        guard key.count == kCCKeySizeAES128 ||
              key.count == kCCKeySizeAES192 ||
              key.count == kCCKeySizeAES256
        else { return false }
        let _iv: Data! = iv == nil ? Data(repeating: 0, count: 16) : iv!
        return CryptoUtil.aesFile(CCOperation(kCCEncrypt), src: self, dst: dst, key: key, iv: _iv)
    }
    
    public func aesDecrypt(dst: URL, key: Data, iv: Data? = nil) -> Bool {
        guard key.count == kCCKeySizeAES128 ||
              key.count == kCCKeySizeAES192 ||
              key.count == kCCKeySizeAES256
        else { return false }
        let _iv: Data! = iv == nil ? Data(repeating: 0, count: 16) : iv!
        return CryptoUtil.aesFile(CCOperation(kCCDecrypt), src: self, dst: dst, key: key, iv: _iv)
    }
    
    public func readPublicKey() -> SecKey? {
        return CryptoUtil.readRSAPublicKey(from: self)
    }
    
    public func readPrivateKey() -> SecKey? {
        return CryptoUtil.readRSAPrivateKey(from: self)
    }
}
