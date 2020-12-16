//
//  Algo.swift
//  Ubiq-Swift
//
//  Created by Prashant on 08/10/20.
//

import Foundation
import CommonCrypto
import OpenSSL

class Algo {
    let UBIQ_HEADER_V0_FLAG_AAD = 0b00000001
    struct AES_GCM {
        var id : Int?
        var key_length : Int?
        var iv_length : Int?
        var tag_length : Int?
        var mode : OpaquePointer? //UnsafePointer<evp_cipher_st>?
    }
    func get_algo(name: String) -> AES_GCM {
        if name == AESAlgo.aes_256.rawValue {
            let aes_256_gcm = AES_GCM.init(id: 0, key_length: 32, iv_length: 12, tag_length: 16,mode: EVP_aes_256_gcm())
            return aes_256_gcm
        }else {
            let aes_128_gcm = AES_GCM.init(id: 1, key_length: 16, iv_length: 12, tag_length: 16, mode: EVP_aes_128_gcm())
            return aes_128_gcm
        }
    }
    func encryptor(algo: AES_GCM,key: Data, iv : Data, aad: Data) -> (OpaquePointer?, Data) {
        // key : A byte string containing the key to be used with this encryption
        // If the caller specifies the initialization vector, it must be
        // the correct length and, if so, will be used.
        if key.count != algo.key_length {
            fatalError(ValidationError.invalidKeyLength.rawValue)
        }
        if iv.count != algo.iv_length {
            fatalError("Invalid initialization vector length")
        }
                
        let ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit (ctx, algo.mode, key.bytes , iv.bytes)
        EVP_EncryptUpdate( ctx, nil, UnsafeMutablePointer<Int32>.allocate(capacity: aad.count), aad.bytes, Int32(aad.count));
        return (ctx, iv)
    }
    func decryptor(algo: AES_GCM,key: Data,iv: Data,aad: Data) -> (OpaquePointer?, Data) {
        if key.count != algo.key_length {
            fatalError(ValidationError.invalidKeyLength.rawValue)
        }
        if iv.count != algo.iv_length {
            fatalError("Invalid initialization vector length")
        }
        let ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit (ctx, algo.mode, key.bytes , iv.bytes)
        EVP_DecryptUpdate( ctx, nil, UnsafeMutablePointer<Int32>.allocate(capacity: aad.count), aad.bytes, Int32(aad.count));
        return (ctx, iv)
    }
}
