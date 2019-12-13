//
//  URL+HTTPUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 13/12/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation

extension URL {
    public func get(header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                    cookies: [String: CustomStringConvertible]? = nil,
                    userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        HTTPUtil.get(url: self, header: header, auth: auth, cookies: cookies, userInfo: userInfo, complete: complete)
    }
    
    public func post(header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                     cookies: [String: CustomStringConvertible]? = nil, data: [String: CustomStringConvertible]? = nil, json: Encodable? = nil,
                     userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        HTTPUtil.post(url: self, header: header, auth: auth, cookies: cookies, data: data, json: json, userInfo: userInfo, complete: complete)
    }
    
    public func put(header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                    cookies: [String: CustomStringConvertible]? = nil, data: [String: CustomStringConvertible]? = nil, json: Encodable? = nil,
                    userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        HTTPUtil.put(url: self, header: header, auth: auth, cookies: cookies, data: data, json: json, userInfo: userInfo, complete: complete)
    }
    
    public func delete(header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                       cookies: [String: CustomStringConvertible]? = nil, data: [String: CustomStringConvertible]? = nil, json: Encodable? = nil,
                       userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        HTTPUtil.delete(url: self, header: header, auth: auth, cookies: cookies, data: data, json: json, userInfo: userInfo, complete: complete)
    }
}
