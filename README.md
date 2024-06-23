# SandBlaster: Reversing the Apple Sandbox

## Supported iOS Versions

This fork was updated to support iOS 16.5-18.0beta sandbox format.

## Cellebrite Fork

Authored by Yarden Hamami of Cellebrite Labs.

## Description
SandBlaster is a tool for reversing (decompiling) binary Apple sandbox profiles. Apple sandbox profiles are written in SBPL (*Sandbox Profile Language*), a Scheme-like language, and are then compiled into an undocumented binary format and shipped. Primarily used on iOS, sandbox profiles are present on macOS as well. SandBlaster is, to our knowledge, the first tool that reverses binary sandbox profiles to their original SBPL format. SandBlaster works on iOS from version 7 onwards including iOS 11.

The technical report [SandBlaster: Reversing the Apple Sandbox](https://arxiv.org/abs/1608.04303) presents extensive (though a bit outdated) information on SandBlaster internals.

SandBlaster relied on previous work by [Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox) and Stefan Esser's [code](https://github.com/sektioneins/sandbox_toolkit) and [slides](https://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements).

The reverser (in the `reverse-sandbox/` folder) runs on any Python running platform.

## Installation

SandBlaster requires Python3 for the reverser (in `reverse-sandbox/`).

## Usage

In order to use SandBlaster you need access to the binary sandbox profiles and the sandbox operations, a set of strings that define sandbox-specific actions. Sandbox profiles and sandbox operations are extracted from the kernel sandbox extension.

```
# Reverse all binary sandbox profiles.
cd ../reverse-sandbox/
mkdir iPad2,1_8.4.1_12H321.reversed_profiles
python3 reverse_sandbox.py -r 17 -o sandbox_operations sandbox_binary_profile -d output_directory/ 
# Generate mach-o output
python3 reverse_sandbox.py -r 17 -c -m -o sandbox_operations sandbox_binary_profile -d output_directory/ 
```

The `-psb` option for `reverse_sandbox.py` prints out the sandbox profiles part of a sandbox bundle without doing the actual reversing.

The `reverse_sandbox.py` script needs to be run in its directory (`reverse-sandbox/`) since it needs the other Python modules and the `logger.config` file.

## Internals

The actual reverser is part of the `reverse-sandbox/` folder. Files here can be categorized as follows:

  * The main script is `reverse_sandbox.py`. It parses the command line arguments, does basic parsing of the input binary file (extracts sections) and calls the appropriate functions from the other modules.
  * The core of the implementation is `operation_node.py`. It provides functions to build the rules graph corresponding to the sandbox profile and to convert the graph to SBPL. It is called by `reverse_sandbox.py`.
  * Sandbox filters (i.e. match rules inside sandbox profiles) are handled by the implementation in `sandbox_filter.py` and the configuration in `filters.json`, `filter_list.py` and `filters.py`. Filter specific functions are called by `operation_node.py`.
  * Regular expression reversing is handled by `sandbox_regex.py` and `regex_parse.py`. `regex_parse.py` is the back end parser that converts the binary representation to a basic graph. `sandbox_regex.py` converts the graph representation (an automaton) to an actual regular expression (i.e. a string of characters and metacharacters). It is called by `reverse_sandbox.py` for parsing regular expressions, with the resulting regular expression list being passed to the functions exposed by `operation_node.py`; `operation_node.py` passes them on to sandbox filter handling files.
  * The new format for storing strings since iOS 10 is handled by `reverse_string.py`. The primary `SandboxString` class in `reverse_string.py` is used in `sandbox_filter.py`.
  * Logging is configured in the `logger.config` file. By default, `INFO` and higher level messages are printed to the console, while `DEBUG` and higher level messages are printed to the `reverse.log` file.
  
## C and Mach-O output

SandBlaster supports decompilation of the sandbox into a C file (`-c`/`--c_output`) rather than Apple's Scheme format. Each operation name is now a function, with `*` being replaced with `$` in function names. While the C output itself is not very readable, it can be compiled into a native executable file (Either manually or by using the `-m`/`--macho` flag), which can be decompiled once more using Hex-Rays Decompiler or a similar decompiler. 

Example output from Hex-Rays:
```c
long dynamic_code_generation()
{
  if ( !entitlement_is_bool_true("dynamic-codesigning") )
    return deny("message 'MAP_JIT requires the dynamic-codesigning entitlement'");
  if ( !process_attribute("is-sandboxed") || process_attribute("is-protoboxed") )
    return deny("message 'MAP_JIT requires sandboxing'");
  return allow("");
}

...

long file_write_data()
{
  if ( file_attribute("sip-protected") )
    return deny("sip-override");
  if ( storage_class_extension("0") )
    return allow("");
  if ( file_attribute("datavault") )
    return deny("sip-override");
  if ( storage_class("MobileBackup") )
  {
    if ( !process_attribute("is-initproc")
      && !process_attribute("is-installer")
      && !signing_identifier("com.apple.filecoordinationd")
      && !entitlement_is_bool_true("com.apple.private.security.storage.MobileBackup") )
    {
      return deny("sip-override");
    }
    goto node_835;
  }
  if ( storage_class("MobileStorageMounter") )
  {
     ...

```


