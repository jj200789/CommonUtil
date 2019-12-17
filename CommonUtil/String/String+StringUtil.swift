//
//  String+StringUtil.swift
//  CommonUtil
//
//  Created by Sam Lam on 5/11/2019.
//  Copyright © 2019 Sam Lam. All rights reserved.
//

import Foundation

extension String {
    public func subString(from position: Int, to index: Int) -> String {
        return StringUtil.subString(self, from: position, to: index)
    }
    
    public func subString(to index: Int) -> String {
        return subString(from: 0, to: index)
    }
    
    public func subString(from position: Int) -> String {
        return subString(from: position, to: self.count)
    }
    
    public subscript(_ range: CountableRange<Int>) -> String {
        return subString(from: range.lowerBound, to: range.upperBound)
    }
    
    public func char(at position: Int) -> String{
        return self[position..<position+1]
    }
    
    public subscript(_ index: Int) -> String {
        return char(at: index)
    }
    
    public func index(of pattern: String) -> Int {
        return StringUtil.index(self, pattern: pattern)
    }
    
    public func index(of pattern: String, from position: Int, to index: Int) -> Int {
        return StringUtil.index(self, pattern: pattern, from: position, to: index)
    }
    
    public func index(of pattern: String, after position: Int) -> Int {
        return index(of: pattern, from: position, to: self.count)
    }
    
    public func index(of pattern: String, before position: Int) -> Int {
        return index(of: pattern, from: 0, to: position)
    }
    
    public func replace(_ pattern: String, with newString: String, from position: Int, to index: Int) -> String {
        return StringUtil.replace(self, pattern: pattern, with: newString, from: position, to: index)
    }
    
    public func replace(_ pattern: String, with newString: String, after position: Int) -> String {
        return replace(pattern, with: newString, from: position, to: self.count)
    }
    
    public func replace(_ pattern: String, with newString: String, before position: Int) -> String {
        return replace(pattern, with: newString, from: 0, to: position)
    }
    
    public func replace(_ pattern: String, with newString: String) -> String {
        return self.replacingOccurrences(of: pattern, with: newString)
    }
    
    public func replace(regex pattern: String, with newString: String, from position: Int, to index: Int) -> String {
        return StringUtil.replace(self, regex: pattern, with: newString, from: position, to: index)
    }
    
    public func replace(regex pattern: String, with newString: String, after position: Int) -> String {
        return replace(pattern, with: newString, from: position, to: self.count)
    }
    
    public func replace(regex pattern: String, with newString: String, before position: Int) -> String {
        return replace(pattern, with: newString, from: 0, to: position)
    }
    
    public func replace(regex pattern: String, with newString: String) -> String {
        return self.replacingOccurrences(of: pattern, with: newString, options: .regularExpression)
    }
    
    public func remove(from postion: Int, to index: Int) -> String {
        return replace(self[postion..<index], with: "", from: postion, to: index)
    }
}
