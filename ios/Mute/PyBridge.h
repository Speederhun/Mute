#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Thin Objective-C wrapper around the embedded CPython runtime.
/// Everything the app does with Python goes through +call:args: (see python/ios_entry.py).
@interface PyBridge : NSObject

/// Starts the interpreter. `bundlePath` is the app bundle; the standard library is expected in
/// <bundle>/python and the app code in <bundle>/app*. Returns nil on success or an error message.
+ (nullable NSString *)startWithBundlePath:(NSString *)bundlePath;

/// Calls ios_entry.call(method, argsJson). Thread safe; blocks while Python works.
/// Returns the JSON text {"ok": ...} or {"error": "..."}.
+ (NSString *)call:(NSString *)method args:(NSString *)argsJson;

@end

NS_ASSUME_NONNULL_END
