# unpyarmor
Deobfuscate / unpack PyArmor obfuscated programs

## Usage
- Extract the encrypted code from the obfuscated file (it should be inside a bytes string as the third argument to ` __pyarmor__`). Write this as raw data to a file, say 'enc.bin'.
- Run `unpyarmor unpack enc.bin pytransform.key out.pyc`, where out.pyc is a pyc file where the decrypted code will be written.
- Use a python decompiler to decompile the decrypted pyc file, e.g. `decompyle3 out.pyc` or `uncompyle6 out.pyc`.

## How?
Well, it turns out PyArmor is slightly wrongly advertised, it is more like a packer or crypter than an obfuscator. Because of this, the python bytecode is still exactly the same, but is just encrypted using the key inside the 'pyarmor.key' file.
It was actually quite a fun challenge to reverse engineer, especially because the key derivation part was using VM obfuscation. However, I managed to extract the algorithm and make a deobfuscator.

## Missing Features
- Python versions other than 3
- Advanced mode
- Super mode
- Possibly some other modes

This tool is in alpha, so if an executable doesn't deobfuscate, create an issue!
