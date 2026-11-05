#import "PyBridge.h"
#import <Python/Python.h>

static PyObject *entryCall = NULL;

@implementation PyBridge

static NSString *statusMessage(PyStatus status) {
    return status.err_msg ? [NSString stringWithUTF8String:status.err_msg] : @"unknown Python error";
}

+ (nullable NSString *)startWithBundlePath:(NSString *)bundlePath {
    if (entryCall) return nil;

    NSString *home = [bundlePath stringByAppendingPathComponent:@"python"];
    setenv("PYTHONUTF8", "1", 1);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);

    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status)) return statusMessage(status);

    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.write_bytecode = 0;
    config.buffered_stdio = 0;
    status = PyConfig_SetBytesString(&config, &config.home, home.UTF8String);
    if (PyStatus_Exception(status)) { PyConfig_Clear(&config); return statusMessage(status); }
    status = PyConfig_Read(&config);
    if (PyStatus_Exception(status)) { PyConfig_Clear(&config); return statusMessage(status); }

    // the app code and the installed packages (the build script copies them into the bundle)
    NSArray<NSString *> *extra = @[@"app", @"app_packages", @"app_packages.iphoneos", @"app_packages.iphonesimulator"];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *name in extra) {
        NSString *dir = [bundlePath stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) continue;
        wchar_t *wide = Py_DecodeLocale(dir.UTF8String, NULL);
        if (!wide) continue;
        status = PyWideStringList_Append(&config.module_search_paths, wide);
        PyMem_RawFree(wide);
        if (PyStatus_Exception(status)) { PyConfig_Clear(&config); return statusMessage(status); }
    }

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) return statusMessage(status);

    PyObject *module = PyImport_ImportModule("ios_entry");
    if (!module) {
        PyErr_Print();
        PyEval_SaveThread();
        return @"Could not import ios_entry (is the app code in the bundle? see ios/README.md)";
    }
    entryCall = PyObject_GetAttrString(module, "call");
    Py_DECREF(module);
    if (!entryCall || !PyCallable_Check(entryCall)) {
        PyErr_Print();
        PyEval_SaveThread();
        return @"ios_entry.call is missing";
    }
    // let other threads take the GIL through PyGILState_Ensure
    PyEval_SaveThread();
    return nil;
}

+ (NSString *)call:(NSString *)method args:(NSString *)argsJson {
    if (!entryCall) return @"{\"error\":\"Python is not running\"}";
    NSString *result = nil;
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *r = PyObject_CallFunction(entryCall, "ss", method.UTF8String, argsJson.UTF8String);
    if (r) {
        const char *utf8 = PyUnicode_AsUTF8(r);
        if (utf8) result = [NSString stringWithUTF8String:utf8];
        Py_DECREF(r);
    } else {
        PyErr_Print();
    }
    PyGILState_Release(gil);
    return result ?: @"{\"error\":\"Python call failed\"}";
}

@end
