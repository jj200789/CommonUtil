//
//  HTTPUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 12/12/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation

public enum HTTPMethod: String {
    case GET, POST, PUT, DELETE
}

public class HTTPResponse {
    let response: HTTPURLResponse?
    let data: Data?
    let error: Error?
    let userInfo: [String: Any]?
    
    init(response: HTTPURLResponse?, data: Data?, error: Error?, userInfo: [String: Any]?) {
        self.response = response
        self.data = data
        self.error = error
        self.userInfo = userInfo
    }
    
    var statusCode: Int {
        return response?.statusCode ?? 400
    }
    
    var header: [String: String] {
        return response?.allHeaderFields as? [String: String] ?? [:]
    }
    
    var cookies: [String: String] {
        guard let url = response?.url else { return [:] }
        let httpCookies = HTTPCookie.cookies(withResponseHeaderFields: header, for: url)
        var cookies: [String: String] =  [:]
        httpCookies.forEach({ cookies[$0.name] = $0.value })
        return cookies
    }
    
    var text: String {
        return String(data: data ?? Data(), encoding: .utf8) ?? ""
    }
    
    func json<T: Decodable>(_ type: T.Type) -> T? {
        if let data = data {
            return try? JSONDecoder().decode(type.self, from: data)
        }
        return nil
    }
}


public class HTTPUtil {
    private static func prepareHeader(_ header: [String: CustomStringConvertible], of request: inout URLRequest) {
        header.forEach({
            request.setValue($0.value.description, forHTTPHeaderField: $0.key)
        })
    }
    
    private static func prepareRequest(method: HTTPMethod, url: URL, data: Data?, header: [String: CustomStringConvertible]) -> URLRequest {
        var request = URLRequest(url: url)
        prepareHeader(header, of: &request)
        request.httpMethod = method.rawValue
        request.httpBody = data
        return request
    }
    
    private static func prepareBody(data: [String: CustomStringConvertible]?, json: Encodable?) -> Data? {
        if let data = data {
            var fields: [String] = []
            data.forEach({ fields.append("\($0.key)=\($0.value.description)") })
            let body = fields.joined(separator: "&")
            return body.data(using: .utf8)
        }
        
        if let json = json {
            return json.json
        }
        
        return nil
    }
    
    private static func prepareCookie(_ cookies: [String: CustomStringConvertible], url: URL) -> [HTTPCookie] {
        var httpCookies: [HTTPCookie] = []
        
        cookies.forEach({
            var httpCookie: [HTTPCookiePropertyKey: Any] = [:]
            httpCookie[.name] = $0.key
            httpCookie[.value] = $0.value.description
            httpCookie[.path] = "/"
            httpCookie[.domain] = url.host!
            httpCookies.append(HTTPCookie(properties: httpCookie)!)
        })
        
        return httpCookies
    }
    
    private static func send(_ method: HTTPMethod,
                             url: URL, header: [String: CustomStringConvertible]?, auth: (String, String)?,
                             cookies: [String: CustomStringConvertible]?, data: [String: CustomStringConvertible]?, json: Encodable?,
                             userInfo: [String: Any]?, complete: ((HTTPResponse) -> Void)? ) {
        var _header = header ?? [:]
        if let auth = auth, let token = "\(auth.0):\(auth.1)".base64EncodedString {
            _header["Authorization"] = "Basic \(token)"
        }
        
        let body = prepareBody(data: data, json: json)
        
        let request = prepareRequest(method: method, url: url, data: body, header: _header)
        
        if let cookies = cookies {
            HTTPCookieStorage.shared.setCookies(prepareCookie(cookies, url: url), for: url, mainDocumentURL: nil)
        }
        
        let task = URLSession(configuration: .default).dataTask(with: request) { (data, response, error) in
            if let complete = complete {
                let httpRep = HTTPResponse(response: response as? HTTPURLResponse, data: data, error: error, userInfo: userInfo)
                complete(httpRep)
            }
        }
        task.resume()
    }
    
    public static func get(url: URL, header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                           cookies: [String: CustomStringConvertible]? = nil,
                           userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        send(.GET, url: url, header: header, auth: auth, cookies: cookies, data: nil, json: nil, userInfo: userInfo, complete: complete)
    }
    
    public static func post(url: URL, header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                            cookies: [String: CustomStringConvertible]? = nil, data: [String: CustomStringConvertible]? = nil, json: Encodable? = nil,
                            userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        send(.POST, url: url, header: header, auth: auth, cookies: cookies, data: data, json: json, userInfo: userInfo, complete: complete)
    }
    
    public static func put(url: URL, header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                           cookies: [String: CustomStringConvertible]? = nil, data: [String: CustomStringConvertible]? = nil, json: Encodable? = nil,
                           userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        send(.PUT, url: url, header: header, auth: auth, cookies: cookies, data: data, json: json, userInfo: userInfo, complete: complete)
    }
    
    public static func delete(url: URL, header: [String: CustomStringConvertible]? = nil, auth: (String, String)? = nil,
                              cookies: [String: CustomStringConvertible]? = nil, data: [String: CustomStringConvertible]? = nil, json: Encodable? = nil,
                              userInfo: [String: Any]? = nil, complete: ((HTTPResponse) -> Void)? = nil) {
        send(.DELETE, url: url, header: header, auth: auth, cookies: cookies, data: data, json: json, userInfo: userInfo, complete: complete)
    }
}


extension Encodable {
    var json: Data? { return try? JSONEncoder().encode(self) }
}
