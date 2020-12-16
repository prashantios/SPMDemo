//
//  Credentials.swift
//  UbiqSample-ios
//
//  Created by Prashant on 30/09/20.
//  Copyright © 2020 Prashant. All rights reserved.
//

import Foundation
import INIParser

class CredentialsInfo {
    var access_key_id = ""
    var secret_signing_key = ""
    var secret_crypto_access_key = ""
    var host = ""
    init(access_key_id: String, secret_signing_key: String, secret_crypto_access_key: String, host: String) {
        self.access_key_id = access_key_id
        self.secret_signing_key = secret_signing_key
        self.secret_crypto_access_key = secret_crypto_access_key
        self.host = host
    }
}

class ConfigCredentials {
    func loadConfigFile(fileName: String, profile: String) -> CredentialsInfo? {
        if let path = Bundle.main.path(forResource: fileName, ofType: "txt")
        {
            do {
                var pro = [String: String]()
                var def = [String: String]()
                let data = try String(contentsOfFile: path, encoding: .utf8)
                let iniParser = try? INIParser.init(string: data)
                if iniParser?.sections["default"] != nil {
                    def = (iniParser?.sections["default"])!
                }
                if def["server"] == nil {
                    def["server"] = UBIQ_HOST
                }
                if iniParser?.sections[profile] != nil {
                    pro = (iniParser?.sections[profile])!
                }
                let accessKey = (pro["ACCESS_KEY_ID"] != nil) ? pro["ACCESS_KEY_ID"] : def["ACCESS_KEY_ID"]
                let secret_signing_key = (pro["SECRET_SIGNING_KEY"] != nil) ? pro["SECRET_SIGNING_KEY"] : def["SECRET_SIGNING_KEY"]
                let secret_crypto_access_key = (pro["SECRET_CRYPTO_ACCESS_KEY"] != nil) ? pro["SECRET_CRYPTO_ACCESS_KEY"] : def["SECRET_CRYPTO_ACCESS_KEY"]
                var host = (pro["SERVER"] != nil) ? pro["SERVER"] : def["SERVER"]
                
                if !(host?.contains("http://"))! && !(host?.contains("https://"))! {
                    host = "https://" + host!
                }
                return CredentialsInfo.init(access_key_id: accessKey!, secret_signing_key: secret_signing_key!, secret_crypto_access_key: secret_crypto_access_key!, host: host!)
            } catch {
                print(error)
            }
        } else {
            print("Unable to open config file")
            return nil
        }
        return nil
    }
}
