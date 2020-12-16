//
//  Enums.swift
//  Ubiq-Swift
//
//  Created by Prashant on 18/10/20.
//

import Foundation

enum AESAlgo : String {
    case aes_128 = "AES-128-GCM"
    case aes_256 = "AES-256-GCM"
}
enum APIMethod : String {
    case GET = "get"
    case POST = "post"
    case PATCH = "patch"
}
enum ValidationError: String {
    case invalidCredentials  = "Some of your credentials are missing, please check!"
    case encryptionNotReady  = "Encryption not ready"
    case encryptionInProgress  = "Encryption already in progress!"
    case encryptionNotStarted  = "Encryption is not started"
    case decryptionNotReady  = "Decryption not ready"
    case decryptionInProgress  = "Decryption already in progress!"
    case decryptionAlreadyStarted  = "Decryption already started!"
    case decryptionNotStarted  = "Decryption is not started"
    case maxKeyExceeded  = "Maximum key uses exceeded"
    case invalidEncHeader = "invalid encryption header"
    case invalidKeyLength = "Invalid key length"
    case invalidIV = "Invalid initialization vector length"
    case inValidTag = "Invalid Tag"
    case invalidCipherDataAndTag = "Invalid cipher data or tag!"
    case somethingWrongWithDate = ""
}

enum error : Error {
    case dateParsingError
}
