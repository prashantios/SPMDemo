//
//  Data.swift
//  Ubiq-Swift
//
//  Created by Prashant on 16/10/20.
//

import Foundation

extension Data {
    func subdata(in range: ClosedRange<Index>) -> Data {
        return subdata(in: range.lowerBound ..< range.upperBound + 1)
    }
}
