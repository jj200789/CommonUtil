//
//  StringUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 22/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation

public class StringUtil {
    public static func subString(_ string: String, from position: Int, to index: Int) -> String {
        if position >= index || index < 0 || position < 0 || index > string.count { return string }
        
        let startIndex = string.index(string.startIndex, offsetBy: position)
        let endIndex = string.index(string.startIndex, offsetBy: min(index, string.count))
        return String(string[startIndex..<endIndex])
    }
    
    public static func index(_ string: String, pattern: String) -> Int {
        guard let lowerBound = string.range(of: pattern)?.lowerBound else { return -1 }
        return string.distance(from: string.startIndex, to: lowerBound)
    }
    
    public static func index(_ string: String, pattern: String, from position: Int, to index: Int) -> Int {
        let startIndex = string.index(string.startIndex, offsetBy: position)
        let endIndex = string.index(string.startIndex, offsetBy: index)
        guard let lowerBound = string.range(of: pattern, options: .caseInsensitive,
                                            range: startIndex..<endIndex)?.lowerBound
        else { return -1 }
        return string.distance(from: string.startIndex, to: lowerBound)
    }
    
    public static func replace(_ string: String, pattern: String, with newString: String, from position: Int, to index: Int) -> String {
        let startIndex = string.index(string.startIndex, offsetBy: position)
        let endIndex = string.index(string.startIndex, offsetBy: index)
        return string.replacingOccurrences(of: pattern, with: newString, options: .caseInsensitive, range: startIndex..<endIndex)
    }
    
    public static func replace(_ string: String, regex pattern: String, with newString: String, from position: Int, to index: Int) -> String {
        let startIndex = string.index(string.startIndex, offsetBy: position)
        let endIndex = string.index(string.startIndex, offsetBy: index)
        return string.replacingOccurrences(of: pattern, with: newString, options: .regularExpression, range: startIndex..<endIndex)
    }
}
