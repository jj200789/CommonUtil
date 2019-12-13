//
//  SecKey+CryptoUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 4/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation

extension SecKey {
    public func savePublicKey(to path: String) -> Bool {
        guard let url = URL(string: path) else { return false }
        return self.savePublicKey(to: url)
    }
    
    public func savePublicKey(to url: URL) -> Bool {
        return CryptoUtil.savePublicKey(self, to: url)
    }
    
    public func savePivateKey(to path: String) -> Bool {
        guard let url = URL(string: path) else { return false }
        return self.savePivateKey(to: url)
    }
    
    public func savePivateKey(to url: URL) -> Bool {
        return CryptoUtil.savePrivateKey(self, to: url)
    }
    
    public func rsaEncrypt(data: Data, algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256) -> Data? {
        return CryptoUtil.rsaEncrypt(data: data, with: self, algorithm: algorithm)
    }
    
    public func rsaEncrypt(msg: String, algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256) -> Data? {
        guard let data = msg.data(using: .utf8) else { return nil }
        return CryptoUtil.rsaEncrypt(data: data, with: self, algorithm: algorithm)
    }
    
    public func rsaDecrypt(data: Data, algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256) -> Data? {
        return CryptoUtil.rsaDecrypt(data: data, with: self, algorithm: algorithm)
    }
    
    public func rsaSign(data: Data, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Data? {
        return CryptoUtil.rsaSign(data: data, with: self, algorithm: algorithm)
    }
    
    public func rsaSign(msg: String, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Data? {
        guard let data = msg.data(using: .utf8) else { return nil }
        return CryptoUtil.rsaSign(data: data, with: self, algorithm: algorithm)
    }
    
    public func rsaVerify(data: Data, signature: Data, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Bool {
        return CryptoUtil.rsaVerify(data: data, signature: signature, with: self, algorithm: algorithm)
    }
}
