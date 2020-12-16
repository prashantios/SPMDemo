//
//  Auth.swift
//  UbiqSample-ios
//
//  Created by Prashant on 30/09/20.
//  Copyright © 2020 Prashant. All rights reserved.
//

import Foundation
import CryptoKit
import CommonCrypto

class Auth {
    func build_header(papi: String, sapi: String, endpoint: String ,query : [String : Any], host: String, http_method: String) -> [String: String] {
        // This function calculates the signature for the message, adding the Signature header
        // to contain the data. Certain HTTP headers are required for
        // signature calculation and will be added by this code as necessary.
        let reqt = "\(http_method) \(endpoint)"
        //The time at which the signature was created.
        let created =  Int(Date().timeIntervalSince1970)
        // convert query to Data to make digest
        let sourceData = self.convertToString(jsonDictionary: query).data(using: .utf8)!
        // Make the body digest
        let digest = "SHA-512=" + sourceData.digestBase64(.sha512)
        var all_headers = [String: String]()
        // The content type of request
        all_headers["content-type"] = "application/json"
        // The request target calculated above(reqt)
        all_headers["(request-target)"] = reqt
        // The date and time in GMT format
        all_headers["date"] = self.getDate()
        // The host specified by the caller
        all_headers["host"] = host
        all_headers["(created)"] = String.init(format: "%d", created)
        all_headers["digest"] = digest
        let arrHeaders = ["content-type","date","host","(created)","(request-target)","digest"]
        var headers = ""
        for header in arrHeaders{
            headers.append("\(header)\(":") \(all_headers[header] ?? "")\n")
        }
        let signatureBase64 = headers.signBase64(.sha512, key: sapi)
        all_headers.removeValue(forKey: "(created)")
        all_headers.removeValue(forKey: "(request-target)")
        all_headers.removeValue(forKey: "host")
        // Build the Signature header itself
        let signature =  String.init(format: "keyId=\"%@\", algorithm=\"hmac-sha512\", created=%d, headers=\"%@\", signature=\"%@\"", papi,created,arrHeaders.joined(separator: " "
        ), signatureBase64)
        all_headers["signature"] = signature
        return all_headers
    }
    func getDate() -> String {
        let formatter = DateFormatter()
        formatter.locale =  Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier:"GMT")
        formatter.dateFormat = "E, dd MMM yyyy HH:mm:ss"
        var date = formatter.string(from: Date())
        date = date + " " + "GMT"
        return date
    }
    func convertToString(jsonDictionary: [String : Any]) -> String {
        do {
            let data = try JSONSerialization.data(withJSONObject: jsonDictionary, options: .fragmentsAllowed)
            return String(data: data, encoding: String.Encoding.utf8) ?? ""
        } catch {
            return ""
        }
    }
}

