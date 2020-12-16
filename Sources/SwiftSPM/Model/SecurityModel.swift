//
//  SecurityModel.swift
//  Ubiq-Swift
//
//  Created by Prashant on 09/10/20.
//

import SwiftyJSON
import Foundation

class SecurityModel: NSObject {
    var enable_data_fragmentation : String = ""
    var algorithm : String = ""

    required init(json : JSON) {
        self.enable_data_fragmentation = json["enable_data_fragmentation"].stringValue
        self.algorithm = json["algorithm"].stringValue
    }

}
