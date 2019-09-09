import os
import math
import string
import hashlib

from collections import Counter

import pefile
import ssdeep
import M2Crypto
import capstone
import ordlookup
import simplejson as json

__VERSION = '1.0 Alpha'

class PEAnalyser():
    __FILE_HEADER = [
        'Machine',  # The architecture type of the computer.
        'NumberOfSections',  # The number of sections.
        'TimeDateStamp',  # The low 32 bits of the time stamp of the image.
        'PointerToSymbolTable',  # The offset of the symbol table, in bytes, or zero if no COFF symbol table exists.
        'NumberOfSymbols',  # The number of symbols in the symbol table.
        'SizeOfOptionalHeader',  # The size of the optional header, in bytes.
        'Characteristics'  # The characteristics of the image.
    ]
    __OPTIONAL_HEADER = [
        'Magic',  # The state of the image file.
        'MajorLinkerVersion',  # The major version number of the linker.
        'MinorLinkerVersion',  # The minor version number of the linker.
        'SizeOfCode', # The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections.
        'SizeOfInitializedData', # The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections.
        'SizeOfUninitializedData', # The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections.
        'AddressOfEntryPoint',  # A pointer to the entry point function, relative to the image base address.
        'BaseOfCode',  # A pointer to the beginning of the code section, relative to the image base.
        'BaseOfData',  # A pointer to the beginning of the data section, relative to the image base.
        'ImageBase',  # The preferred address of the first byte of the image when it is loaded in memory.
        'SectionAlignment',  # The alignment of sections loaded in memory, in bytes.
        'FileAlignment',  # The alignment of the raw data of sections in the image file, in bytes.
        'MajorOperatingSystemVersion',  # The major version number of the required operating system.
        'MinorOperatingSystemVersion',  # The minor version number of the required operating system.
        'MajorImageVersion',  # The major version number of the image.
        'MinorImageVersion',  # The minor version number of the image.
        'MajorSubsystemVersion',  # The major version number of the subsystem.
        'MinorSubsystemVersion',  # The minor version number of the subsystem.
        'Reserved1',  # (Win32VersionValue) This member is reserved and must be 0.
        'SizeOfImage',  # The size of the image, in bytes, including all headers.
        'SizeOfHeaders', # The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.
        'CheckSum',  # The image file checksum.
        'Subsystem',  # The subsystem required to run this image.
        'DllCharacteristics',  # The DLL characteristics of the image.
        'SizeOfStackReserve',  # The number of bytes to reserve for the stack.
        'SizeOfStackCommit',  # The number of bytes to commit for the stack.
        'SizeOfHeapReserve',  # The number of bytes to commit for the local heap.
        'SizeOfHeapCommit',  # This member is obsolete.
        'LoaderFlags',  # The number of directory entries in the remainder of the optional header.
        'NumberOfRvaAndSizes'  # A pointer to the first IMAGE_DATA_DIRECTORY structure in the data directory.
    ]

    def __init__(self, file_path):
        self.info = dict()
        file_name = os.path.basename(file_path)
        with open(file_path, 'rb') as f:
            file_data = f.read()

        self.info['FileName'] = file_name
        self.info['FileSize'] = len(file_data)
        self.info['hash'] = self.__get_hash(file_data)

        self.set_fuzzy_hash(file_data)
        self.set_strings(file_data)
        try:
            self.pe = pefile.PE(data = file_data)
            self.info['PE'] = dict()
            self.set_info_from_pe()
        except pefile.PEFormatError as e:
            print('PEFormatError')

    def __get_hash(self, file_data):
        return {'md5' : hashlib.md5(file_data).hexdigest(), 'sha1' : hashlib.sha1(file_data).hexdigest(), 'sha256' : hashlib.sha256(file_data).hexdigest()}

    def __get_file_ratio(self, data):
        return len(data) / self.info['FileSize']

    def set_info_from_pe(self):
        self.set_info_from_file_header()
        self.set_info_from_optional_header()
        self.set_info_from_imports()
        self.set_info_from_exports()
        self.set_info_from_section()
        self.set_certification_info()
        self.set_info_from_resources()

    def set_info_from_file_header(self):
        if hasattr(self.pe, 'FILE_HEADER'):
            self.info['PE']['FILE_HEADER'] = dict()
            for member in PEAnalyser.__FILE_HEADER:
                self.info['PE']['FILE_HEADER'][member] = getattr(self.pe.FILE_HEADER, member, None)

    def set_info_from_optional_header(self):
        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            self.info['PE']['OPTIONAL_HEADER'] =  dict()
            for member in PEAnalyser.__OPTIONAL_HEADER:
                self.info['PE']['OPTIONAL_HEADER'][member] = getattr(self.pe.OPTIONAL_HEADER, member, None)
            if hasattr(self.pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
                self.info['PE']['OPTIONAL_HEADER']['DATA_DIRECTORY'] = dict()
                for structure in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                    self.info['PE']['OPTIONAL_HEADER']['DATA_DIRECTORY'][structure.name] = dict()
                    self.info['PE']['OPTIONAL_HEADER']['DATA_DIRECTORY'][structure.name]['VirtualAddress'] = structure.VirtualAddress
                    self.info['PE']['OPTIONAL_HEADER']['DATA_DIRECTORY'][structure.name]['Size'] = structure.Size

    def set_info_from_imports(self):
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            self.info['PE']['import'] = []
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                import_info = dict()
                if isinstance(entry.dll, bytes):
                    libname = entry.dll.decode().lower()
                else:
                    libname = entry.dll.lower()
                import_info['Library'] = libname
                import_info['Functions'] = []
                for imp in entry.imports:
                    if not imp.name:
                        funcname = ordlookup.ordLookup(entry.dll.lower(), imp.ordinal, make_name=True)
                        if not funcname:
                            raise Exception("Unable to look up ordinal %s:%04x" % (entry.dll, imp.ordinal))
                    else:
                        funcname = imp.name
                    if not funcname:
                        continue
                    if isinstance(funcname, bytes):
                        funcname = funcname.decode()
                    if imp.import_by_ordinal:
                        import_info['Functions'].append({'Address' : imp.address, 'Name' : funcname, 'Ordinal' : imp.ordinal})
                    else:
                        import_info['Functions'].append({'Address': imp.address, 'Name': funcname})
                self.info['PE']['import'].append(import_info)

    def set_info_from_exports(self):
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            self.info['PE']['exports'] = dict()
            libname = self.pe.DIRECTORY_ENTRY_EXPORT.name
            if isinstance(libname, bytes):
                libname = libname.decode().lower()
            else:
                libname = libname.dll.lower()
            self.info['PE']['exports']['Name'] = libname
            self.info['PE']['exports']['Functions'] = []
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not exp.name:
                    funcname = ordlookup.ordLookup(libname, exp.ordinal, make_name=True)
                    if not funcname:
                        raise Exception("Unable to look up ordinal %s:%04x" % (libname, exp.ordinal))
                else:
                    funcname = exp.name
                if not funcname:
                    continue
                if not funcname:
                    continue
                if isinstance(funcname, bytes):
                    funcname = funcname.decode()
                self.info['PE']['exports']['Functions'].append({'Name' : funcname, 'Address' : exp.address, 'Ordinal' : exp.ordinal})

    def __is_executable(self, characteristics):
        if characteristics & 0x20 == 0x20 and characteristics & 0x20000000 == 0x20000000:
            return True
        else:
            return False

    def __is_writable(self, characteristics):
        if characteristics & 0x80000000 == 0x80000000:
            return True
        else:
            return False

    def set_info_from_section(self):
        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        if hasattr(self.pe, 'sections'):
            self.info['PE']['sections'] = []
            for section in self.pe.sections:
                try:
                    section_name = str(section.Name, 'utf-8').encode('ascii', errors='ignore').strip().decode('ascii').strip(' \t\r\n\0')
                except:
                    section_name = str(section.Name, 'ISO-8859-1').encde('ascii', errors='ignore').strip().decode('ascii').strip(' \t\r\n\0')
                if section_name == '':
                    section_name = '.noname'
                section_data = section.get_data()
                section_info = dict()
                section_info['Name'] = section_name
                section_info['Characteristics'] = section.Characteristics
                section_info['VirtualAddress'] = section.VirtualAddress
                section_info['VirtualSize'] = section.Misc_VirtualSize
                section_info['SizeOfRawData'] = section.SizeOfRawData
                section_info['hash'] = {
                    'md5' : section.get_hash_md5(),
                    'sha1' : section.get_hash_sha1(),
                    'sha256' : section.get_hash_sha256()
                }
                section_info['entropy'] = section.get_entropy()
                section_info['executable'] = self.__is_executable(section.Characteristics)
                section_info['writable'] = self.__is_writable(section.Characteristics)
                section_info['file_ratio'] = self.__get_file_ratio(section_data)
                if section_info['executable']:
                    tmp2 = []
                    for code_line in dis.disasm(section_data, 0x1000):
                        tmp2.append([
                            code_line.address,
                            ' '.join([format(each_byte, '02x') for each_byte in code_line.bytes]),
                            '{}'.format(code_line.mnemonic).strip(),
                            '{}'.format(code_line.op_str).strip()
                        ])
                    if len(tmp2) != 0:
                        section_info['asm'] = tmp2
                    else:
                        section_info['data'] = ' '.join([format(each_byte, '02x') for each_byte in section_data])
                else:
                    section_info['data'] = ' '.join([format(each_byte, '02x') for each_byte in section_data])
                self.info['PE']['sections'].append(section_info)

    def set_fuzzy_hash(self, data):
        self.info['FuzzyHash'] = {
            'ssdeep' : ssdeep.hash(data)
        }

    def set_strings(self, data):
        printable = set(string.printable)
        self.info['Strings'] = []
        found_str = ""
        for char in data:
            try:
                char = chr(char)
                if char in printable:
                    found_str += char
                elif len(found_str) >= 4:
                    self.info['Strings'].append(found_str)
                    found_str = ""
                else:
                    found_str = ""
            except:
                found_str = ""
        if len(found_str) >= 4:
            self.info['Strings'].append(found_str)

    # From pefile
    def __get_entropy(slef, data):
        """Calculate the entropy of a chunk of data."""

        if not data:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

        return entropy

    def set_info_from_resources(self):
        res_array = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                raw_data = self.pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
                                ent = self.__get_entropy(raw_data)
                                raw_data = [format(i, '02x') for i in raw_data]
                                lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                                sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang,resource_lang.data.sublang)
                                file_ratio = self.__get_file_ratio(raw_data)
                                res_array.append({"name": name,
                                                  "data": raw_data,
                                                  "offset": hex(resource_lang.data.struct.OffsetToData),
                                                  "size": resource_lang.data.struct.Size,
                                                  "entropy" : ent,
                                                  "language": lang,
                                                  "sublanguage": sublang})
        if len(res_array) != 0:
            self.info['PE']['Resource'] = res_array

    # Frome peframe
    def set_certification_info(self):
        result = {}
        cert_address = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        cert_size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

        if cert_address != 0 and cert_size != 0:
            signature = self.pe.write()[cert_address + 8:]
            details = {}

            bio = M2Crypto.BIO.MemoryBuffer(bytes(signature))
            if bio:
                pkcs7_obj = M2Crypto.m2.pkcs7_read_bio_der(bio.bio_ptr())
                if pkcs7_obj:
                    p7 = M2Crypto.SMIME.PKCS7(pkcs7_obj)
                    for cert in p7.get0_signers(M2Crypto.X509.X509_Stack()) or []:
                        subject = cert.get_subject()
                        try:
                            serial_number = "%032x" % cert.get_serial_number()
                        except:
                            serial_number = ''
                        try:
                            common_name = subject.CN
                        except:
                            common_name = ''
                        try:
                            country = subject.C
                        except:
                            country = ''
                        try:
                            locality = subject.L
                        except:
                            locality = ''
                        try:
                            organization = subject.O
                        except:
                            organization = ''
                        try:
                            email = subject.Email
                        except:
                            email = ''
                        try:
                            valid_from = cert.get_not_before()
                        except:
                            valid_from = ''
                        try:
                            valid_to = cert.get_not_after()
                        except:
                            valid_to = ''
                        details.update({
                            "serial_number": str(serial_number),
                            "common_name": str(common_name),
                            "country": str(country),
                            "locality": str(locality),
                            "organization": str(organization),
                            "email": str(email),
                            "valid_from": str(valid_from),
                            "valid_to": str(valid_to),
                            "hash": {
                                "sha1": "%040x" % int(cert.get_fingerprint("sha1"), 16),
                                "md5": "%032x" % int(cert.get_fingerprint("md5"), 16),
                                "sha256": "%064x" % int(cert.get_fingerprint("sha256"), 16)
                            }
                        })

            result.update({
                "virtual_address": cert_address,
                "block_size": cert_size,
                "details": details
            })
            self.info['PE']['Certification'] = result

    def dump_json(self, json_path):
        json_dir_path = os.path.split(json_path)[0]
        abspath = os.path.abspath(json_dir_path)
        if not os.path.isdir(abspath):
            os.makedirs(abspath)
        with open(json_path, 'w') as f:
            json.dump(self.info, f)

    def dump_dict(self):
        return self.info