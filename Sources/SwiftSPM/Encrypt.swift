//
//  Encrypt.swift
//  Ubiq-Swift
//
//  Created by Prashant on 18/10/20.
//

import Foundation
import Alamofire
import SwiftyJSON
import CommonCrypto
import OpenSSL

public class Encrypt {
    var encryptionKeys :  EncryptionKeys?
    var algo : Algo.AES_GCM?
    var encryptor : OpaquePointer? // = UnsafeMutablePointer<EVP_CIPHER_CTX>?
    var host = ""
    var papi = ""
    var sapi = ""
    var srsa = ""
    var encryption_started = false
    var encryption_ready = true
    var baseURL : String = ""
    
     init?(cred: CredentialsInfo, uses: Int) {
        if !validateCredentials(credentials: cred) {
            fatalError(ValidationError.invalidCredentials.rawValue)
        }
        // Set host, either the default or the one given by caller
        self.host = cred.host
        self.baseURL = cred.host
        self.host = (self.host == "") ? UBIQ_HOST : self.getHost()
        // The client's public API key (used to identify the client to the server
        self.papi = cred.access_key_id
        // The client's secret API key (used to authenticate HTTP requests)
        self.sapi = cred.secret_signing_key
        // The client's secret RSA encryption key/password (used to decrypt the client's RSA key from the server). This key is not retained by this object.
        self.srsa = cred.secret_crypto_access_key
        // Build the Request Body with the number of uses of key provided
        let query = ["uses": uses]
        // Retrieve the necessary headers to make the request using Auth Object
        let headers = Auth().build_header(papi: self.papi, sapi: self.sapi,endpoint: self.endpoint() ,query: query, host: self.host, http_method: APIMethod.POST.rawValue.lowercased())
        self.encryption_started = false
        self.encryption_ready = true
        // Build the request into a variable
        let urlRequest = Alamofire.request(URL.init(string: self.baseURL + self.endpoint())!, method: .post, parameters: query, encoding: JSONEncoding.default, headers: headers)
        let (data, response, error) = URLSession.shared.synchronousDataTask(urlrequest: urlRequest.request!)
        if let error = error {
            print("error: \(error)")
        }
        else {
            if let httpResponse = response as? HTTPURLResponse{
                if (httpResponse.statusCode == 201) {
                    if data != nil {
                        let JSONResponse = try? JSON.init(data: data!)
                        print(JSONResponse)
                        self.encryptionKeys = EncryptionKeys.init(json: JSONResponse!)
                        let wdk = Data.init(base64Encoded: self.encryptionKeys!.wrapped_data_key)
                        self.encryptionKeys?.encrypted_private_key = (self.encryptionKeys?.encrypted_private_key.replacingOccurrences(of: "\r", with: ""))!
                        ERR_load_CRYPTO_strings()
                        OpenSSL_add_all_algorithms()
//                        ERR_load_crypto_strings()
//                        OPENSSL_add_all_algorithms_noconf()
                        
                        let bio = BIO_new_mem_buf(self.encryptionKeys?.encrypted_private_key.bytes, Int32((self.encryptionKeys?.encrypted_private_key.count)!))
                        let passPhrase = UnsafeMutablePointer(mutating: (self.srsa as NSString).utf8String)
                        //PEM_read_bio_RSAPrivateKey   //PEM_read_bio_PrivateKey
                        let rsa_privatekey = PEM_read_bio_RSAPrivateKey(bio, nil, nil, passPhrase)
                        
                        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
                        let wk = RSA_private_decrypt(Int32(wdk!.count), wdk?.bytes, output, rsa_privatekey, RSA_PKCS1_OAEP_PADDING);
                        let a = UnsafeMutableBufferPointer.init(start: output, count: Int(wk))
                        let b = Array(a)
                    
                        self.encryptionKeys?.raw = Data.init(bytes: b, count: Int(wk))
                        self.encryptionKeys?.uses = 0
                        self.algo = Algo().get_algo(name: (self.encryptionKeys?.securityModel!.algorithm)!)
                    }
                }else {
                    print("HTTPError Response: Expected 201")
                }
            }
        }
    }
    
    // Begin the encryption process
    func begin() -> Data? {
        // When this function is called, the encryption object increments
        // the number of uses of the key and creates a new internal context
        // to be used to encrypt the data.
        // If the encryption object is not yet ready to be used, throw an error
        if !self.encryption_ready {
            fatalError(ValidationError.encryptionNotReady.rawValue)
        }
        // if Encryption cipher context already exists
        if self.encryption_started {
            fatalError(ValidationError.encryptionInProgress.rawValue)
        }
        // Encryption object can not be nil.
        if self.encryptionKeys == nil {
            print("Something went wrong. Please check.")
            return nil
        }
        // If max uses > uses
        if self.encryptionKeys!.uses >= self.encryptionKeys!.max_uses {
            fatalError(ValidationError.maxKeyExceeded.rawValue)
        }
        self.encryptionKeys?.uses = +1
        guard let iv = self.randomGenerateBytes(count: 12) else {return nil}
        // create the struct
        let newStruct =  [0, Algo().UBIQ_HEADER_V0_FLAG_AAD, self.algo?.id, iv.count, self.encryptionKeys?.encrypted?.count]
        // Pack the result into bytes to get a byte string
        let dataStruct = pack("!BBBBH", newStruct as [Any])
        // create additional authentocation data(AAD) for more security.
        let aad = dataStruct + iv + (self.encryptionKeys?.encrypted)!
        // create a new Encryption context and initialization vector
        let encAlgo = Algo().encryptor(algo: self.algo!, key: self.encryptionKeys!.raw!,iv: iv,aad: aad)
        self.encryptor = encAlgo.0
        self.encryption_started = true
        return  dataStruct + encAlgo.1 + (self.encryptionKeys?.encrypted)!
    }
    func update(data: Data) -> Data? {
        if !self.encryption_started {
            fatalError(ValidationError.encryptionNotStarted.rawValue)
        }
        // aggregate partial results
        // Encryption of some plain text is perfomed here
        // Any cipher text produced by the operation is returned
        
        let outbuf = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        let outlen =  UnsafeMutablePointer<Int32>.allocate(capacity: data.count)
        EVP_EncryptUpdate (self.encryptor, outbuf, outlen, data.bytes, Int32(data.count));
        let dataBuffer = Data(bytes: outbuf, count: data.count)
        return dataBuffer
    }
    func end() -> Data {
        if !self.encryption_started {
            fatalError(ValidationError.encryptionNotStarted.rawValue)
        }
        // This function finalizes the encryption (producing the final
        // cipher text for the encryption, if necessary) and adds any
        // authentication information (if required by the algorithm).
        // Any data produced is returned by the function.
        let tagBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        EVP_EncryptFinal (self.encryptor, tagBuffer, UnsafeMutablePointer<Int32>.allocate(capacity: 16));
        EVP_CIPHER_CTX_ctrl (self.encryptor, EVP_CTRL_GCM_GET_TAG, 16, tagBuffer);
        self.encryption_started = false
        let tagData = Data(bytes: tagBuffer, count: 16)
        return tagData
    }
    func close() {
        if self.encryption_started {
            fatalError("Encryption currently running")
        }
        // If the key was used less times than was requested, send an update to the server
        if self.encryptionKeys!.uses < self.encryptionKeys!.max_uses {
            let queryURL = self.endpoint() + "/" + self.encryptionKeys!.key_fingerprint + "/" + self.encryptionKeys!.encryption_session
            let query = ["actual": self.encryptionKeys?.uses, "requested": self.encryptionKeys?.max_uses]
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
                        self.encryption_ready = false
                    }else {
                        print("HTTPError Response: Expected 201")
                    }
                }
            }
        }
    }
    func endpoint_base() -> String {
        return self.host + "/api/v0"
    }
    func endpoint() -> String {
        return "/api/v0/encryption/key"
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
        // This method checks for the presence of the credentials
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
public class Encryption {
    public init() {}
    public func encrypt(creds: CredentialsInfo, data: Data) -> Data? {
        let enc = Encrypt.init(cred: creds, uses: 5)
        do {
            guard let begin = enc?.begin() else {
                return nil
            }
            guard let update = enc?.update(data: data) else {
                return nil
            }
            guard let end = enc?.end() else {
                return nil
            }
            // combine begin, update and end data
            let res = begin + update + end
            if enc?.encryptionKeys != nil {
                enc?.close()
            }
            return res
        }
        catch {
            print("Something went wrong with data..Please try again.")
        }
    }
}
