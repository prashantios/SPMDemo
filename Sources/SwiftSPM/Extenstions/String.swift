//
//  String.swift
//  UbiqSample-ios
//
//  Created by Prashant on 05/10/20.
//  Copyright © 2020 Prashant. All rights reserved.
//

import Foundation

extension String {
    //: ### Base64 encoding a string
    func base64Encoded() -> String? {
        if let data = self.data(using: .utf8) {
            return data.base64EncodedString()
        }
        return nil
    }
    //: ### Base64 decoding a string
    func base64Decoded() -> String? {
        if let data = Data(base64Encoded: self, options: Data.Base64DecodingOptions(rawValue: 0)) {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }
    func hexString() -> String{
        let data = Data(self.utf8)
        let hexString = data.map{ String(format:"%02x", $0) }.joined()
        return hexString
    }
    func toHexEncodedString(uppercase: Bool = true, prefix: String = "", separator: String = "") -> String {
            return unicodeScalars.map { prefix + .init($0.value, radix: 16, uppercase: uppercase) } .joined(separator: separator)
        }
}
