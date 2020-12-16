//
//  URLSession.swift
//  Ubiq-Swift
//
//  Created by Prashant on 20/10/20.
//

import Foundation

extension URLSession {
    func synchronousDataTask(urlrequest: URLRequest) -> (data: Data?, response: URLResponse?, error: Error?) {
        var data: Data?
        var response: URLResponse?
        var error: Error?
        let semaphore = DispatchSemaphore(value: 0)
        let dataTask = self.dataTask(with: urlrequest) {
            data = $0
            response = $1
            error = $2
            semaphore.signal()
        }
        dataTask.resume()
        _ = semaphore.wait(timeout: .distantFuture)
        return (data, response, error)
    }
}
