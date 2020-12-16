//
//  EncryptionKeys.swift
//  Ubiq-Swift
//
//  Created by Prashant on 09/10/20.
//

import SwiftyJSON
import Foundation

class EncryptionKeys: NSObject {
    var encrypted_private_key : String = ""
    //var new_dk : String = ""
    var key_fingerprint : String = ""
    var encryption_session : String = ""
    var max_uses : Int = 0
    var uses : Int = 0
    var encrypted_data_key : String = ""
    var encrypted : Data?
    var wrapped_data_key : String = ""
    var securityModel : SecurityModel?
    var raw : Data?
    // Decryption
    var client_id : String = ""
    
    required init(json : JSON) {
        // Get encrypted private key from response body
        self.encrypted_private_key = json["encrypted_private_key"].stringValue
        //self.new_dk = "12345678901234567890123456789012".base64Encoded()! //json["new_dk"].stringValue
        self.key_fingerprint = json["key_fingerprint"].stringValue
        self.encryption_session = json["encryption_session"].stringValue
        self.max_uses = json["max_uses"].intValue
        self.encrypted_data_key = json["encrypted_data_key"].stringValue
        self.encrypted = Data.init(base64Encoded: self.encrypted_data_key)
        // Get wrapped data key from response body
        self.wrapped_data_key = json["wrapped_data_key"].stringValue
        self.securityModel = SecurityModel.init(json: json["security_model"])
        
        // For Decription
    }

}
