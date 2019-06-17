#!/usr/bin/python
#
# travreg.py is a Python script to enumerate URL handlers in order to
# aid in the discovery of protocol handler-related vulnerabilities.
#
# Based on https://github.com/ChiChou/LookForSchemes/blob/master/AppSchemes.cpp
#
# written by Julio Cesar Fort
# Copyright 2016-2019, Blaze Information Security

import platform
import winreg

VERBOSE = False

def _check_windows():
    if platform.system() == 'Windows':
        return True
    else:
        return False


def _subkeys(keyname):
    i = 0
    while True:
        try:
            subkey = winreg.EnumKey(keyname, i)
            yield subkey
            i+=1
        except WindowsError as e:
            break


def _traverse_keys(keyname):
    if VERBOSE:
        print("Opening key: HKEY_CLASSES_ROOT\\%s" % keyname)
    key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, keyname)
    
    try:
        _ = winreg.QueryValueEx(key, "URL Protocol")
        if VERBOSE:
            print("KEY_CLASSES_ROOT\\%s" % keyname)
        
        query_default = winreg.QueryValueEx(key, "")
        if 'URL' in query_default[0]:
            print(query_default[0]) 
        
        open_cmd = "%s%s" % (keyname, "\\shell\\open\\command")
        if VERBOSE:
            print(open_cmd)
        
        print("\t%s" % winreg.QueryValue(winreg.HKEY_CLASSES_ROOT, open_cmd))
    except FileNotFoundError:
        pass
    except OSError:
        pass
    
    
    for subkey_name in _subkeys(key):
        subkey_path = "%s\\%s" % (keyname, subkey_name)
        if VERBOSE:
            print(subkey_path)
        _traverse_keys(subkey_path)
    
    return
    

def main():
    list_keys = []
    
    if not _check_windows():
        print("[!] This code only works on Windows. Quitting...")
        return
    
    print("Traversing the registry for app schemes...")    
    try:
        _check_reg_access = winreg.QueryInfoKey(winreg.HKEY_CLASSES_ROOT)
        n_keys = _check_reg_access[0]
    except Exception as err:
        print("[!] Cannot open key 'HKEY_CLASSES_ROOT'. Quitting...")
        return
    
    print("Found %d keys" % n_keys)
    
    for i in range(n_keys):
        list_keys.append(winreg.EnumKey(winreg.HKEY_CLASSES_ROOT, i).title())
        
    for z in range(n_keys):
        _traverse_keys(list_keys[z])

if __name__ == '__main__':
    main()
