//
//  Decrypt.swift
//  Ubiq-Swift
//
//  Created by Prashant on 16/10/20.
//

import Foundation
import Alamofire
import SwiftyJSON
import CommonCrypto
import OpenSSL

public class Decrypt {
    var encryptionKeys :  EncryptionKeys?
    var algo : Algo.AES_GCM?
    var decryptor : OpaquePointer?
    var host = ""
    var papi = ""
    var sapi = ""
    var srsa = ""
    var baseURL : String = ""
    var decryption_started = false
    var decryption_ready = true
    var encData = Data()
    
    public init?(cred: CredentialsInfo, uses: Int) {
        if !validateCredentials(credentials: cred) {
            fatalError(ValidationError.invalidCredentials.rawValue)
        }
        self.host = cred.host
        self.baseURL = cred.host
        self.host = (self.host == "") ? UBIQ_HOST : self.getHost()
        // The client's public API key (used to identify the client to the server
        self.papi = cred.access_key_id
        // The client's secret API key (used to authenticate HTTP requests)
        self.sapi = cred.secret_signing_key
        // The client's secret RSA encryption key/password (used to decrypt the
        // client's RSA key from the server). This key is not retained by this object.
        self.srsa = cred.secret_crypto_access_key
        self.decryption_ready = true
        self.decryption_started = false
    }
    public func begin() -> Data {
        // Begin the decryption process
        if !self.decryption_ready {
            fatalError(ValidationError.decryptionNotReady.rawValue)
        }
        if self.decryption_started {
            fatalError(ValidationError.decryptionAlreadyStarted.rawValue)
        }
        self.decryption_started = true
        return self.encData
    }
    public func update(encData: Data) -> Data? {
        // Append the incoming data in the internal data buffer
        self.encData = self.encData + encData
        if !self.decryption_started {
            fatalError(ValidationError.decryptionNotStarted.rawValue)
        }
        // if there is no key or decryptor, then the code is still trying to build a complete header
        if self.encryptionKeys == nil || self.decryptor == nil {
            let struct_length = pack("!BBBBH", [1,1,1,1,1]).count
            if self.encData.count > struct_length {
                let packed_struct = self.encData.subdata(in: 0..<struct_length)
                // Unpack the values packed in encryption
                let unpackStruct = try? unpack("!BBBBH", packed_struct)
                let version = unpackStruct?[0] as? Int
                guard let flags = unpackStruct?[1] as? Int else {return nil}
                guard let ivLength = unpackStruct?[3] as? Int else {return nil}
                guard let keyLength = unpackStruct?[4] as? Int else {return nil}
                // verify version is 0 and flags are correct
                if version != 0 || (flags & ~Algo().UBIQ_HEADER_V0_FLAG_AAD) != 0 {
                    fatalError(ValidationError.invalidEncHeader.rawValue)
                }
                if self.encData.count > struct_length + ivLength + keyLength {
                    // Extract the initialization vector
                    let iv = self.encData.subdata(in: struct_length..<struct_length + ivLength)
                    // Extract the encryped key
                    let encrypted_key = self.encData.subdata(in: (struct_length + ivLength)..<(keyLength + struct_length + ivLength))
                    // Remove the header from the buffer
                    self.encData = self.encData.subdata(in: (keyLength + struct_length + ivLength) ..< self.encData.count)
                    // generate a local identifier for the key
                    let clientId = encrypted_key.digestData(.sha512)
                    if self.encryptionKeys != nil {
                        if self.encryptionKeys?.client_id != String(decoding: clientId, as: UTF8.self) {
                            self.close()
                        }
                    }
                    // IF key object not exists, request a new one from the server
                    if self.encryptionKeys == nil {
                        let query = ["encrypted_data_key": encrypted_key.base64EncodedString()]
                        let headers = Auth().build_header(papi: papi, sapi: sapi,endpoint: self.endpoint() ,query: query, host: self.host, http_method: APIMethod.POST.rawValue.lowercased())
                        let urlRequest = Alamofire.request(URL.init(string: self.baseURL + self.endpoint())!, method: .post, parameters: query, encoding: JSONEncoding.default, headers: headers)
                        let (data, response, error) = URLSession.shared.synchronousDataTask(urlrequest: urlRequest.request!)
                        if let error = error {
                            print("error: \(error)")
                        }
                        else {
                            if let httpResponse = response as? HTTPURLResponse {
                                if (httpResponse.statusCode == 200) {
                                    let JSONResponse = try? JSON.init(data: data!)
                                    print(JSONResponse)
                                    self.encryptionKeys = EncryptionKeys.init(json: JSONResponse!)
                                    let wdk = Data.init(base64Encoded: self.encryptionKeys!.wrapped_data_key)
                                    self.encryptionKeys?.encrypted_private_key = (self.encryptionKeys?.encrypted_private_key.replacingOccurrences(of: "\r", with: ""))!
//                                    ERR_load_crypto_strings()
//                                    OPENSSL_add_all_algorithms_noconf()
                                    ERR_load_CRYPTO_strings()
                                    OpenSSL_add_all_algorithms()
                                    let bio = BIO_new_mem_buf(self.encryptionKeys?.encrypted_private_key.bytes, Int32((self.encryptionKeys?.encrypted_private_key.count)!))
                                    let passPhrase = UnsafeMutablePointer(mutating: (self.srsa as NSString).utf8String)
                                    //PEM_read_bio_RSAPrivateKey   //PEM_read_bio_PrivateKey
                                    let rsa_privatekey = PEM_read_bio_RSAPrivateKey(bio, nil, nil, passPhrase)
                                    
                                    let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
                                    let wk = RSA_private_decrypt(Int32(wdk!.count), wdk?.bytes, output, rsa_privatekey, RSA_PKCS1_OAEP_PADDING);
                                    let a = UnsafeMutableBufferPointer.init(start: output, count: Int(wk))
                                    let b = Array(a)
                                    self.encryptionKeys?.raw = Data.init(bytes: b, count: 32)
                                    self.encryptionKeys?.client_id = String(decoding: clientId, as: UTF8.self)
                                    self.encryptionKeys?.uses = 0
                                }else {
                                    print("HTTPError Response: Expected 201")
                                }
                            }
                        }
                    }
                    if self.encryptionKeys != nil {
                        self.algo = Algo().get_algo(name: AESAlgo.aes_256.rawValue)
                        // Create aad using packed struct , iv and encrypted_key
                        let aad = packed_struct + iv + encrypted_key
                        let decAlgo = Algo().decryptor(algo: self.algo!, key: self.encryptionKeys!.raw!,iv: iv,aad: aad)
                        self.decryptor = decAlgo.0
                        self.encryptionKeys?.uses = +1
                    }
                }
            }
        }
        if self.encryptionKeys != nil && self.decryptor != nil {
            let size = self.encData.count - (algo?.tag_length)!
            if size > 0 {
                let outbuf = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
                let outlen =  UnsafeMutablePointer<Int32>.allocate(capacity: size)
                let dataWithoutTag = self.encData.subdata(in: 0..<size)
                EVP_DecryptUpdate (self.decryptor, outbuf, outlen, dataWithoutTag.bytes, Int32(dataWithoutTag.count));
                let dataBuffer = Data(bytes: outbuf, count: dataWithoutTag.count)
                print(String(decoding: dataBuffer, as: UTF8.self))
                self.encData = self.encData.subdata(in: size..<self.encData.count)
                //self.encData.removeAll()
                return dataBuffer
            }
        }
        return nil
    }
    public func end() -> Data? {
        if !self.decryption_started {
            fatalError(ValidationError.decryptionNotStarted.rawValue)
        }
        // Finish the decryption
        let len = EVP_CIPHER_CTX_block_size(self.decryptor);
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: self.encData.count)
        buf.initialize(from: self.encData.bytes, count: 16)
        let buflen = UnsafeMutablePointer<Int32>.allocate(capacity: Int(len))
        EVP_CIPHER_CTX_ctrl (self.decryptor, EVP_CTRL_GCM_SET_TAG, 16, buf)
        let b = EVP_DecryptFinal(self.decryptor, buf, buflen)
        if b == 0 {
            print("Invalid cipher data and tag")
            return nil
        }
        self.decryption_started = false
        EVP_CIPHER_CTX_free(self.decryptor)
        self.encData.removeAll()
        return self.encData
    }
    public func close() {
        if self.decryption_started {
            fatalError("Decryption currently running")
        }
        // Reset the internal state of the decryption object
        //"http://127.0.0.1:3000"
        if self.encryptionKeys != nil {
            if self.encryptionKeys!.uses > 0 {
                let queryURL = self.endpoint() + "/" + self.encryptionKeys!.key_fingerprint + "/" + self.encryptionKeys!.encryption_session
                let query = ["uses": self.encryptionKeys?.uses]
                let headers = Auth().build_header(papi: self.papi, sapi: self.sapi,endpoint: queryURL ,query: query as [String : Any], host: self.host, http_method: APIMethod.PATCH.rawValue.lowercased())
                let urlRequest = Alamofire.request(URL.init(string: self.baseURL + queryURL)!, method: .patch, parameters: query as Parameters, encoding: JSONEncoding.default, headers: headers)
                let (data, response, error) = URLSession.shared.synchronousDataTask(urlrequest: urlRequest.request!)
                if let error = error {
                    print("error: \(error)")
                }
                else {
                    if let httpResponse = response as? HTTPURLResponse {
                        if (httpResponse.statusCode == 204) {
                            let JSONResponse = try? JSON.init(data: data!)
                            print(JSONResponse)
                            self.encryptionKeys = nil
                            self.decryptor = nil
                        }else {
                            print("HTTPError Response: Expected 201")
                        }
                    }
                }
            }
        }
    }
    func endpoint_base() -> String {
        return self.host + "/api/v0"
    }
    func endpoint() -> String {
        return "/api/v0/decryption/key"
    }
    func getHost() -> String {
        let url =  URL.init(string: self.host)
        if url?.port != nil {
            return (url?.host)! + ":" + String((url?.port)!)
        }else{
            return (url?.host)!
        }
    }
    func validateCredentials(credentials : CredentialsInfo) -> Bool {
        return (credentials.access_key_id.isEmpty || credentials.secret_signing_key.isEmpty || credentials.secret_crypto_access_key.isEmpty) ? false : true
    }
    func randomGenerateBytes(count: Int) -> Data? {
        let bytes = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 1)
        defer { bytes.deallocate() }
        let status = CCRandomGenerateBytes(bytes, count)
        guard status == kCCSuccess else { return nil }
        return Data(bytes: bytes, count: count)
    }
}
public class Decryption {
    public init() {}
    public func decrypt(creds: CredentialsInfo, data: Data) -> Data? {
        let dec = Decrypt.init(cred: creds, uses: 1)
        do {
            guard let begin = dec?.begin() else {
                return nil
            }
            guard let update = dec?.update(encData: data) else {
                return nil
            }
            guard let end = dec?.end() else {
                return nil
            }
            let arrdec = [begin, update, end].compactMap({ $0 })
            var combineData = Data()
            for data in arrdec {
                combineData = combineData + data
            }
            dec?.close()
            return combineData
        }
        catch {
            print("Something wrong with cipher data.Please try again.")
        }
    }
}
