import os
import math
import string
import hashlib

from collections import Counter

import pefile
import peutils
import ssdeep
import M2Crypto
import capstone
import patoolib
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
    __COMPID_DICT = {
            0: "Unknown",
            1: "Import0",
            2: "Linker510",
            3: "Cvtomf510",
            4: "Linker600",
            5: "Cvtomf600",
            6: "Cvtres500",
            7: "Utc11_Basic",
            8: "Utc11_C",
            9: "Utc12_Basic",
            10: "Utc12_C",
            11: "Utc12_CPP",
            12: "AliasObj60",
            13: "VisualBasic60",
            14: "Masm613",
            15: "Masm710",
            16: "Linker511",
            17: "Cvtomf511",
            18: "Masm614",
            19: "Linker512",
            20: "Cvtomf512",
            21: "Utc12_C_Std",
            22: "Utc12_CPP_Std",
            23: "Utc12_C_Book",
            24: "Utc12_CPP_Book",
            25: "Implib700",
            26: "Cvtomf700",
            27: "Utc13_Basic",
            28: "Utc13_C",
            29: "Utc13_CPP",
            30: "Linker610",
            31: "Cvtomf610",
            32: "Linker601",
            33: "Cvtomf601",
            34: "Utc12_1_Basic",
            35: "Utc12_1_C",
            36: "Utc12_1_CPP",
            37: "Linker620",
            38: "Cvtomf620",
            39: "AliasObj70",
            40: "Linker621",
            41: "Cvtomf621",
            42: "Masm615",
            43: "Utc13_LTCG_C",
            44: "Utc13_LTCG_CPP",
            45: "Masm620",
            46: "ILAsm100",
            47: "Utc12_2_Basic",
            48: "Utc12_2_C",
            49: "Utc12_2_CPP",
            50: "Utc12_2_C_Std",
            51: "Utc12_2_CPP_Std",
            52: "Utc12_2_C_Book",
            53: "Utc12_2_CPP_Book",
            54: "Implib622",
            55: "Cvtomf622",
            56: "Cvtres501",
            57: "Utc13_C_Std",
            58: "Utc13_CPP_Std",
            59: "Cvtpgd1300",
            60: "Linker622",
            61: "Linker700",
            62: "Export622",
            63: "Export700",
            64: "Masm700",
            65: "Utc13_POGO_I_C",
            66: "Utc13_POGO_I_CPP",
            67: "Utc13_POGO_O_C",
            68: "Utc13_POGO_O_CPP",
            69: "Cvtres700",
            70: "Cvtres710p",
            71: "Linker710p",
            72: "Cvtomf710p",
            73: "Export710p",
            74: "Implib710p",
            75: "Masm710p",
            76: "Utc1310p_C",
            77: "Utc1310p_CPP",
            78: "Utc1310p_C_Std",
            79: "Utc1310p_CPP_Std",
            80: "Utc1310p_LTCG_C",
            81: "Utc1310p_LTCG_CPP",
            82: "Utc1310p_POGO_I_C",
            83: "Utc1310p_POGO_I_CPP",
            84: "Utc1310p_POGO_O_C",
            85: "Utc1310p_POGO_O_CPP",
            86: "Linker624",
            87: "Cvtomf624",
            88: "Export624",
            89: "Implib624",
            90: "Linker710",
            91: "Cvtomf710",
            92: "Export710",
            93: "Implib710",
            94: "Cvtres710",
            95: "Utc1310_C",
            96: "Utc1310_CPP",
            97: "Utc1310_C_Std",
            98: "Utc1310_CPP_Std",
            99: "Utc1310_LTCG_C",
            100: "Utc1310_LTCG_CPP",
            101: "Utc1310_POGO_I_C",
            102: "Utc1310_POGO_I_CPP",
            103: "Utc1310_POGO_O_C",
            104: "Utc1310_POGO_O_CPP",
            105: "AliasObj710",
            106: "AliasObj710p",
            107: "Cvtpgd1310",
            108: "Cvtpgd1310p",
            109: "Utc1400_C",
            110: "Utc1400_CPP",
            111: "Utc1400_C_Std",
            112: "Utc1400_CPP_Std",
            113: "Utc1400_LTCG_C",
            114: "Utc1400_LTCG_CPP",
            115: "Utc1400_POGO_I_C",
            116: "Utc1400_POGO_I_CPP",
            117: "Utc1400_POGO_O_C",
            118: "Utc1400_POGO_O_CPP",
            119: "Cvtpgd1400",
            120: "Linker800",
            121: "Cvtomf800",
            122: "Export800",
            123: "Implib800",
            124: "Cvtres800",
            125: "Masm800",
            126: "AliasObj800",
            127: "PhoenixPrerelease",
            128: "Utc1400_CVTCIL_C",
            129: "Utc1400_CVTCIL_CPP",
            130: "Utc1400_LTCG_MSIL",
            131: "Utc1500_C",
            132: "Utc1500_CPP",
            133: "Utc1500_C_Std",
            134: "Utc1500_CPP_Std",
            135: "Utc1500_CVTCIL_C",
            136: "Utc1500_CVTCIL_CPP",
            137: "Utc1500_LTCG_C",
            138: "Utc1500_LTCG_CPP",
            139: "Utc1500_LTCG_MSIL",
            140: "Utc1500_POGO_I_C",
            141: "Utc1500_POGO_I_CPP",
            142: "Utc1500_POGO_O_C",
            143: "Utc1500_POGO_O_CPP",
            144: "Cvtpgd1500",
            145: "Linker900",
            146: "Export900",
            147: "Implib900",
            148: "Cvtres900",
            149: "Masm900",
            150: "AliasObj900",
            151: "Resource900",
            152: "AliasObj1000",
            154: "Cvtres1000",
            155: "Export1000",
            156: "Implib1000",
            157: "Linker1000",
            158: "Masm1000",
            170: "Utc1600_C",
            171: "Utc1600_CPP",
            172: "Utc1600_CVTCIL_C",
            173: "Utc1600_CVTCIL_CPP",
            174: "Utc1600_LTCG_C ",
            175: "Utc1600_LTCG_CPP",
            176: "Utc1600_LTCG_MSIL",
            177: "Utc1600_POGO_I_C",
            178: "Utc1600_POGO_I_CPP",
            179: "Utc1600_POGO_O_C",
            180: "Utc1600_POGO_O_CPP",
            183: "Linker1010",
            184: "Export1010",
            185: "Implib1010",
            186: "Cvtres1010",
            187: "Masm1010",
            188: "AliasObj1010",
            199: "AliasObj1100",
            201: "Cvtres1100",
            202: "Export1100",
            203: "Implib1100",
            204: "Linker1100",
            205: "Masm1100",
            206: "Utc1700_C",
            207: "Utc1700_CPP",
            208: "Utc1700_CVTCIL_C",
            209: "Utc1700_CVTCIL_CPP",
            210: "Utc1700_LTCG_C ",
            211: "Utc1700_LTCG_CPP",
            212: "Utc1700_LTCG_MSIL",
            213: "Utc1700_POGO_I_C",
            214: "Utc1700_POGO_I_CPP",
            215: "Utc1700_POGO_O_C",
            216: "Utc1700_POGO_O_CPP",
        }

    def __init__(self, file_path):
        self.info = dict()
        file_name = os.path.basename(file_path)
        with open(file_path, 'rb') as f:
            self.file_data = f.read()

        self.info['FileName'] = file_name
        self.info['FileSize'] = len(self.file_data)
        self.info['hash'] = self.__get_hash(self.file_data)

        self.set_fuzzy_hash(self.file_data)
        self.set_strings(self.file_data)
        try:
            self.pe = pefile.PE(data = self.file_data)
            self.info['PE'] = dict()
            self.set_info_from_pe()
        except pefile.PEFormatError as e:
            print('PEFormatError')

    def __get_hash(self, file_data):
        return {'md5' : hashlib.md5(file_data).hexdigest(), 'sha1' : hashlib.sha1(file_data).hexdigest(), 'sha256' : hashlib.sha256(file_data).hexdigest()}

    def __get_file_ratio(self, data):
        return len(data) / self.info['FileSize']

    def set_info_from_pe(self):
        self.set_file_header_info()
        self.set_optional_header_info()
        self.set_imports_info()
        self.set_exports_info()
        self.set_section_info()
        self.set_resources_info()
        self.set_tls_info()
        self.set_rich_header_info()
        self.set_signatures_info()
        self.set_certification_info()
        self.set_overlay_info()

    def set_overlay_info(self):
        overlay_offset = self.pe.get_overlay_data_start_offset()
        if overlay_offset:
            overlay = {}
            overlay["Offset"] = overlay_offset
            overlay["Size"] = self.info['FileSize'] - overlay_offset
            overlay["FileRatio"] = overlay["Size"] / self.info['FileSize']
            self.info['PE']['overlay'] = overlay

    def set_signatures_info(self):
        signatures = peutils.SignatureDatabase('userdb.txt')
        matches = signatures.match_all(self.pe, ep_only=True)
        signatures_set = set()
        if matches:
            for item in matches:
                if item[0] not in signatures_set:
                    signatures_set.add(item[0])
        if len(signatures_set) != 0:
            self.info['PE']['signatures'] = list(signatures_set)

    def set_file_header_info(self):
        if hasattr(self.pe, 'FILE_HEADER'):
            self.info['PE']['FILE_HEADER'] = dict()
            for member in PEAnalyser.__FILE_HEADER:
                self.info['PE']['FILE_HEADER'][member] = getattr(self.pe.FILE_HEADER, member, None)

    def set_optional_header_info(self):
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

    def set_imports_info(self):
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

    def set_exports_info(self):
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

    def set_section_info(self):
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
                elif len(found_str) >= 6:
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
        if not data:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

        return entropy

    def set_resources_info(self):
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

    def set_rich_header_info(self):
        if hasattr(self.pe, 'RICH_HEADER'):
            rich_header = []
            for i in range(0, len(getattr(self.pe.RICH_HEADER, 'values', [])), 2):
                comp_id = self.pe.RICH_HEADER.values[i]
                comp_cnt = self.pe.RICH_HEADER.values[i + 1]
                comp_name = self.__COMPID_DICT.get(comp_id, '*unknown*')
                rich_header.append({"id" : comp_id, "count" : comp_cnt, "name" : comp_name})
            if len(rich_header) != 0:
                self.info['PE']['RichHeader'] = rich_header

    # Freom peframe
    def set_tls_info(self):
        for d in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.name == "IMAGE_DIRECTORY_ENTRY_TLS":
                tls_directories = self.pe.parse_directory_tls(d.VirtualAddress, d.Size).struct
                self.info['PE']['TLS'] = {
                    "StartAddressOfRawData": tls_directories.StartAddressOfRawData,
                    "EndAddressOfRawData": tls_directories.EndAddressOfRawData,
                    "AddressOfIndex": tls_directories.AddressOfIndex,
                    "AddressOfCallBacks": tls_directories.AddressOfCallBacks,
                    "SizeOfZeroFill": tls_directories.SizeOfZeroFill,
                    "Characteristics": tls_directories.Characteristics,
                }
                break

    def set_debug_info(self):
        DEBUG_TYPE = {
            "IMAGE_DEBUG_TYPE_UNKNOWN": 0,
            "IMAGE_DEBUG_TYPE_COFF": 1,
            "IMAGE_DEBUG_TYPE_CODEVIEW": 2,
            "IMAGE_DEBUG_TYPE_FPO": 3,
            "IMAGE_DEBUG_TYPE_MISC": 4,
            "IMAGE_DEBUG_TYPE_EXCEPTION": 5,
            "IMAGE_DEBUG_TYPE_FIXUP": 6,
            "IMAGE_DEBUG_TYPE_BORLAND": 9,
        }
        result = {}
        for d in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.name == "IMAGE_DIRECTORY_ENTRY_DEBUG":
                debug_directories = self.pe.parse_debug_directory(d.VirtualAddress, d.Size)
                for debug_directory in debug_directories:
                    if debug_directory.struct.Type == DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"]:
                        result.update({
                            "PointerToRawData": debug_directory.struct.PointerToRawData,
                            "size": debug_directory.struct.SizeOfData
                        })
                self.info['PE']['debug'] = result
                break

    # Frome peframe
    def set_relocations_info(self):
        result = {}
        for d in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.name == "IMAGE_DIRECTORY_ENTRY_BASERELOC": break
            result.update({"VirtualAddress": d.VirtualAddress, "Size": d.Size})
            reloc_directories = self.pe.parse_relocations_directory(d.VirtualAddress, d.Size)
            result.update({"count": len(reloc_directories)})
            i = 0
            my_items = {}
            for items in reloc_directories:
                i = i + 1
                for item in items.entries:
                    my_items.update({"reloc_" + str(i): len(items.entries)})
            result.update({"details": my_items})
            self.info['PE']['relocations'] = result

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
        if 'PE' in self.info and 'overlay' in self.info['PE']:
            # temp
            self.dump_overlay(os.path.splitext(json_path)[0] + '.7z')

    def dump_overlay(self, overlay_path):
        if 'PE' in self.info and 'overlay' in self.info['PE']:
            with open(overlay_path, 'wb') as f:
                f.write(self.file_data[self.info['PE']['overlay']["Offset"]:])
            try:
                patoolib.extract_archive(overlay_path)
            except Exception as e:
                print(e)

    def dump_dict(self):
        return self.info