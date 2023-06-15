package zip
import "core:fmt"

import "core:mem"
import "core:os"
import "core:bytes"
import "core:compress/zlib"
import z "vendor:zlib"
import "core:path/filepath"
import "core:hash"

LOCAL_FILE_SIGNATURE      :: 0x04034b50
CENTRAL_DIR_SIGNATURE     :: 0x02014b50
DIGITAL_SIGNATURE         :: 0x05054b50
END_CENTRAL_DIR_SIGNATURE :: 0x06054b50

Version_Made_By :: enum u16 {
	MS_DOS         = 0,
	Amiga          = 1,
	OpenVMS        = 2,
	UNIX           = 3,
	VM_CMS         = 4,
	Atari_ST       = 5,
	OS_2           = 6,
	Macintosh      = 7,
	Z_System       = 8,
	CP_M           = 9,
	Windows_NTFS   =10,
	MVS            =11,
	VSE            =12,
	Acorn_Risc     =13,
	VFAT           =14,
	alternate_MVS  =15,
	BeOS           =16,
	Tandem         =17,
	OS_400         =18,
	OSX            =19,
}

Version_Needed_To_Extract :: struct #packed {
	a, b: byte,
}

Compression_Method :: enum u16 {
	no_compression     = 0,
	Shrunk             = 1,
	Reduced_1          = 2,
	Reduced_2          = 3,
	Reduced_3          = 4,
	Reduced_4          = 5,
	Imploded           = 6,
	Deflated           = 8,
	Enhanced_Deflating = 9,
	PKWARE_Imploding   = 10,
	BZIP2              = 12,
	LZMA               = 14,
	CMPSC              = 16,
	IBM_TERSE          = 18,
	IBM_LZ77           = 19,
	deprecated         = 20,
	Zstandard          = 93, 
	MP3                = 94, 
	XZ                 = 95, 
	JPEG               = 96, 
	WavPack            = 97,
	PPMd               = 98,
	AE_x               = 99,
}

Flags :: enum u16 {
	encrypted_file          = 0,
	compression_option_a    = 1,
	compression_option_b    = 2,
	data_descriptor         = 3,
	enhanced_deflation      = 4,
	compressed_patched_data = 5,
	strong_encryption       = 6,
	language_encoding       = 11,
	mask_header_values      = 13,
}

get_comp_options :: proc(flags:bit_set[Flags]) -> string {
	A := (.compression_option_a in flags)
	B := (.compression_option_b in flags)

	if !A && !B {
		return "Normal"
	} else if A && !B {
		return "Maximum"
	} else if !A && A {
		return "Fast"
	} else if A && B {
		return "SuperFast"
	}

	return "NIL"
}

Time :: u16
Date :: u16

Extra_Fields :: enum {
		Macintosh                                       = 0x07c8,
		Pixar_USD_header_ID                             = 0x1986,
		ZipIt_Macintosh                                 = 0x2605,
		ZipIt_Macintosh_1_3_5                           = 0x2705,
		ZipIt_Macintosh_1_3_5_                          = 0x2805,
		Info_ZIP_Macintosh                              = 0x334d,
		Tandem                                          = 0x4154,
		Acorn_SparkFS                                   = 0x4341,
		Windows_NT_security_descriptor                  = 0x4453,
		VM_CMS                                          = 0x4704,
		MVS                                             = 0x470f,
		THEOS                                           = 0x4854,
		FWKCS_MD5                                       = 0x4b46,
		OS_2_access_control_list                        = 0x4c41,
		Info_ZIP_OpenVMS                                = 0x4d49,
		Macintosh_Smartzip                              = 0x4d63,
		Xceed_original_location_extra_field             = 0x4f4c,
		AOS_VS                                          = 0x5356,
		extended_timestamp                              = 0x5455,
		Xceed_unicode_extra_field                       = 0x554e,
		Info_ZIP_UNIX                                   = 0x5855,
		Info_ZIP_Unicode_Comment_Extra_Field            = 0x6375,
		BeOS_BeBox                                      = 0x6542,
		THEOS_                                          = 0x6854,
		Info_ZIP_Unicode_Path_Extra_Field               = 0x7075,
		AtheOS_Syllable                                 = 0x7441,
		ASi_UNIX                                        = 0x756e,
		Info_ZIP_UNIX_                                  = 0x7855,
		Info_ZIP_UNIX__                                 = 0x7875,
		Data_Stream_Alignment                           = 0xa11e,
		Microsoft_Open_Packaging_Growth_Hint            = 0xa220,
		Java_JAR_file_Extra_Field_Header_ID             = 0xcafe,
		Android_ZIP_Alignment_Extra_Field               = 0xd935,
		Korean_ZIP_code_page_info                       = 0xe57a,
		SMS_QDOS                                        = 0xfd4a,
		AE_x_encryption_structure                       = 0x9901,
		unknown                                         = 0x9902,
}

Local_File_Header :: struct #packed {
	signature:              u32,                // local file header signature     4 bytes  (0x04034b50)
	version_needed:         u16,                // 2 bytes
	flags:                  bit_set[Flags],     // 2 bytes

	compression_method:     Compression_Method, // compression method              2 bytes
	last_mod_time:          Time,               // last mod file time              2 bytes
	last_mod_date:          Date,               // last mod file date              2 bytes

	crc_32:                 u32,                // crc-32                          4 bytes

	compressed_size:        u32,                // compressed size                 4 bytes
	uncompressed_size:      u32,                // uncompressed size               4 bytes
	file_name_length:       u16,                // file name length                2 bytes
	extra_field_length:     u16,                // extra field length              2 bytes
	// file_name:              string,          // file name (variable size)
	// extra_field:            rawptr,          // extra field (variable size)
}

Central_Directory_Header :: struct #packed {
	signature:           u32,
	version:             u16,
	version_needed:      u16,
	flags:               bit_set[Flags],
	compression:         u16,
	last_mod_time:       Time,
	last_mod_date:       Date,
	crc_32:              u32,
	compressed_size:     u32,
	uncompressed_size:   u32,
	file_name_length:    u16,
	extra_field_length:  u16,
	file_comment_length: u16,
	disk_number_start:   u16,
	internal_attribute:  u16,
	external_attribute:  u32,
	offset_local_header: u32,
}


End_Central_Directory :: struct #packed {	
	signature:                  u32, // 4 bytes  (0x06054b50)
	disk_number:                u16, // 2 bytes
	disk_width_central_dir:     u16, // 2 bytes
	num_entries_this_disk:      u16, // 2 bytes
	num_entries:				    u16, // 2 bytees
	size_dir:                   u32, // 4 bytes
	offset:                     u32, // 4 bytes
	comment_length:             u16, // 2 bytes
}

// Data_Descriptor :: struct {
// 	crc_32:            u32, //4 bytes
// 	compressed_size:   u32, //4 bytes
// 	uncompressed_size: u32, //4 bytes
// }

// Extra_Field :: struct {
// 	archive_extra_data_signature: u32,    //4 bytes  (0x08064b50)
// 	extra_field_length:           u32,    //4 bytes
// 	extra_field_data:             rawptr, //(variable size)
// }

// Digital_Signature :: struct {
// 	header_signature:  u32,    // 4 bytes  (0x05054b50)
// 	size_of_data:      u16,    // 2 bytes
// 	signature_data:    rawptr, //(variable size)
// }

Local_File :: struct {
	name:         string,
	fullname:     string,
	ext:          string,
	extra:        []byte,
	header:       Local_File_Header,
	raw_data:     []byte,
	data:         []byte,
}

Central_Dir_Record :: struct {
	name:         string,
	fullname:     string,
	ext:          string,
	comment:      string,
	extra:        []byte,
	header:       Central_Directory_Header,
}

Zip_File :: struct {
	buf:                 []byte,
	full_path:           string,
	files:               [dynamic]Local_File,
	records:             [dynamic]Central_Dir_Record,
	// digital_signature:   Digital_Signature,
	end_of_directory:    End_Central_Directory,
	comment:             string,
}

read :: proc(full_path:string) -> Zip_File {
	fmt.println(">>>>>>> BEGIN >>>>>>>")
	zip_file : Zip_File
	ok:bool

	// read file into memory
	zip_file.buf, ok = os.read_entire_file(full_path)
	if !ok { fmt.println("Error?", ok); return zip_file }

	zip_file.full_path = full_path
	
	scan := true
	pos: int = 0
	for scan {
		signature := ((^u32)(&zip_file.buf[pos]))^
		switch signature {
			case LOCAL_FILE_SIGNATURE:
				header: Local_File_Header
				header = (cast(^Local_File_Header)(raw_data(zip_file.buf[pos:])))^
				
				name_begin  := pos + size_of(Local_File_Header)
				name        := string(zip_file.buf[name_begin:name_begin + int(header.file_name_length)])
				
				extra_begin := name_begin + len(name)
				extra       := zip_file.buf[extra_begin:extra_begin + int(header.extra_field_length)]

				local_file: Local_File
				local_file.header   = header
				local_file.name     = filepath.base(name)
				local_file.ext      = filepath.ext(name)
				local_file.fullname = name
				local_file.extra    = extra

				// fmt.println(">> LOCAL FILE", name)
				if len(extra) > 0 do fmt.println("FOUND", string(extra))

				raw_data_begin := extra_begin + int(header.extra_field_length)
				local_file.raw_data = zip_file.buf[raw_data_begin:raw_data_begin + int(header.compressed_size)]
				
				fmt.println("read size", header.compressed_size, name)

				inflate_file(&local_file)

				append(&zip_file.files, local_file)
				pos += size_of(Local_File_Header) + int(header.file_name_length) + int(header.extra_field_length) + int(header.compressed_size)

			case CENTRAL_DIR_SIGNATURE:
				header:    Central_Directory_Header
				header   = (cast(^Central_Directory_Header)(raw_data(zip_file.buf[pos:])))^

				name_begin  := pos + size_of(Central_Directory_Header)
				name        := string(zip_file.buf[name_begin:name_begin + int(header.file_name_length)])
				
				extra_begin := name_begin + int(header.file_name_length)
				extra       := zip_file.buf[extra_begin:extra_begin + int(header.extra_field_length)]

				comment_begin := pos + size_of(Central_Directory_Header) + int(header.file_name_length) + int(header.extra_field_length)
				comment     := string(zip_file.buf[comment_begin:comment_begin + int(header.file_comment_length)])
				
				record: Central_Dir_Record
				record.header    = header
				record.name      = filepath.base(name)
				record.ext       = filepath.ext(name)
				record.fullname  = name
				record.extra     = extra
				record.comment   = comment

				// fmt.println(">> CENTRAL DIR RECORD", name)
				append(&zip_file.records, record)
				pos += size_of(Central_Directory_Header) + int(header.file_name_length) + int(header.extra_field_length) + int(header.file_comment_length)

			case DIGITAL_SIGNATURE:
				fmt.println(">> Found digital signature...")

			case END_CENTRAL_DIR_SIGNATURE:
				scan = false
				fmt.println(">> END CENTRAL DIR")

				zip_file.end_of_directory = (cast(^End_Central_Directory)(raw_data(zip_file.buf[pos:])))^
				pos += size_of(End_Central_Directory)
				comment_length := int(zip_file.end_of_directory.comment_length)

				if comment_length > 0 {
					zip_file.comment = string(zip_file.buf[pos:pos+comment_length])
				} else {
					zip_file.comment = ""
				}

				pos += comment_length
		}
	}
	fmt.println(">> Loaded file!")
	return zip_file
}

inflate_file :: proc(file:^Local_File) {
	buf: bytes.Buffer
	defer bytes.buffer_destroy(&buf)
	#partial switch file.header.compression_method {
		case .Deflated:
			// fmt.println(">> from file raw size <<", len(file.raw_data))
			// fmt.println("uncompressed_size", file.name, ":", file.header.uncompressed_size)
			err := zlib.inflate(input=file.raw_data, buf=&buf, expected_output_size=int(file.header.uncompressed_size), raw=true)
			if err != nil {
				fmt.printf("\nInflate Error: %v\n", err)
			} else {
				file.data = make([]byte, len(buf.buf))
				copy_slice(file.data, buf.buf[:])
			}
			crc := hash.crc32(file.data)
			assert(crc == file.header.crc_32)
			// fmt.println("buf size", len(buf.buf))
		case .no_compression:
			file.data = make([]byte, len(file.raw_data))
			copy(file.data, file.raw_data)
		case:
			assert(0!=0, "only works with deflate or no compression...")
	}
}

compress_alt :: proc(input_data:[]byte) -> []byte {
	using z
	dest:= make([]byte, 4096*10)

	strm: z_stream
	strm.zalloc = nil
	strm.zfree = nil
	strm.opaque = nil

	strm.avail_in = u32(len(input_data))       // size of input, string + terminator
	strm.next_in = raw_data(input_data)        // input char array
	strm.avail_out = 4096*10                   // size of output
	strm.next_out = raw_data(dest)             // output char array
	
	// the actual compression work.
	// z_streamp  level, method, windowBits, memLevel, strategy
	err := deflateInit2(strm=&strm, level=DEFLATED, method=DEFLATED, windowBits=-15, memLevel=8, strategy=DEFAULT_STRATEGY)
	fmt.println("init err", err)
	if err < 0 do assert(false)
	
	// res := OK
	// for res != STREAM_END {
	res := deflate(&strm, FINISH)
	fmt.println("deflate err", err)
	assert(res >= 0)
	// }

	result := dest[:strm.total_out]
	compressed_size := strm.total_out

	deflateEnd(&strm)
	return result
}

// NOTE allocated memory
compress :: proc(input_data:[]byte) -> []byte {
	using z
	input_len:= u32(len(input_data))
	fmt.println("compress raw size", len(input_data))
	initial_dest_size := compressBound(input_len)
	dest := make([]byte, initial_dest_size)
	dest_len: uLongf = initial_dest_size
	err := compress(raw_data(dest), &dest_len, raw_data(input_data), input_len)
	fmt.println("compressed size", dest_len)
	return dest[:dest_len]
}

free_compress :: proc(buf:[]byte) { delete(buf) }

// assumes you just have changed local_file.data and rezips
zip_deflate :: proc(zip_file: ^Zip_File, input_files_data:[][]byte, output_path:string) {
	// fmt.println(">> OUT >> Starting to deflate and zip:", zip_file.full_path, ">>", output_path)

	// alloc mem
	output_buffer: [dynamic]byte
	defer delete(output_buffer)
	reserve(&output_buffer, len(zip_file.buf))
	dest_sizes := make([]u32, len(zip_file.files))
	defer delete(dest_sizes)
	offsets := make([]u32, len(zip_file.files))
	defer delete(offsets)

	pos:int
	// output each file_header & file data, compress if necessary
	for file, fi in &zip_file.files {
		offsets[fi] = u32(pos)

		new_header: Local_File_Header
		mem.copy(&new_header, &file.header, size_of(Local_File_Header))

		raw_data := input_files_data[fi]

		compressed_file_data: []byte
		defer delete(compressed_file_data)
		
		#partial switch file.header.compression_method {
			case .Deflated:
				// compressed_file_data = compress(raw_data)
				compressed_file_data = compress_alt(raw_data)
				new_header.compressed_size = u32(len(compressed_file_data))
				
				// fmt.println("deflating size", new_header.compressed_size, len(compressed_file_data))

				// compressed_file_data = raw_data
				// new_header.compressed_size = u32(len(raw_data))
				// new_header.compression_method = .no_compression
			case .no_compression:
				compressed_file_data = raw_data
				new_header.compressed_size = u32(len(raw_data))
			case:
				assert(0 != 0, "Only supports Deflated or no compression..")
		}

		assert(compressed_file_data != nil)
		assert(!(.data_descriptor in new_header.flags))

		dest_sizes[fi] = new_header.compressed_size
		name_len := new_header.file_name_length
		extra_len := new_header.extra_field_length

		// resize file buffer if need be
		end := pos + size_of(Local_File_Header) + int(name_len) + int(extra_len) + int(new_header.compressed_size)
		if end > len(output_buffer) do resize(&output_buffer, end + 4)

		mem.copy(&output_buffer[pos], &new_header, size_of(Local_File_Header))
		pos += size_of(Local_File_Header)

		copy(output_buffer[pos:], file.fullname)
		pos += int(new_header.file_name_length)
		
		mem.copy(&output_buffer[pos], &file.extra, int(new_header.extra_field_length))
		pos += int(new_header.extra_field_length)
		
		copy(output_buffer[pos:], compressed_file_data)
		pos += int(new_header.compressed_size)

		assert(len(compressed_file_data) == int(new_header.compressed_size))
		assert(len(file.fullname) == int(new_header.file_name_length))
		assert(len(file.extra) == int(new_header.extra_field_length))
	}
	
	size_files := pos

	// RECORDS
	for record, ri in &zip_file.records {
		// fmt.println(">> OUT >> Zipping record", record.name)
		dest_len := dest_sizes[ri]
				
		new_header: Central_Directory_Header
		mem.copy(&new_header, &record.header, size_of(Central_Directory_Header))
		new_header.compressed_size = dest_len
		assert(record.name == zip_file.files[ri].name)
		new_header.offset_local_header = offsets[ri]

		name_len := new_header.file_name_length
		extra_len := new_header.extra_field_length
		comment_len := new_header.file_comment_length

		// resize if need be
		end := pos + size_of(Central_Directory_Header) + int(name_len) + int(extra_len) + int(comment_len)
		if end > len(output_buffer) {
			resize(&output_buffer, end+4)
		}

		// copy header
		mem.copy(&output_buffer[pos], &new_header, size_of(Central_Directory_Header))
		pos += size_of(Central_Directory_Header)
	
		// copy file fullname
		copy(output_buffer[pos:], record.fullname)
		assert(int(new_header.file_name_length) == len(record.fullname))
		pos += len(record.fullname)

		// copy extra field
		mem.copy(&output_buffer[pos], &record.extra, int(new_header.extra_field_length))
		pos += int(new_header.extra_field_length)

		// copy comment
		if comment_len > 0 {
			// copy(output_buffer[pos:], dest[:int(dest_len)])
		}
		pos += int(comment_len)
	}
	
	if len(output_buffer) < pos + size_of(End_Central_Directory) + int(zip_file.end_of_directory.comment_length) {
		resize(&output_buffer, pos + size_of(End_Central_Directory) + int(zip_file.end_of_directory.comment_length))
	}

	fmt.println("END SIZE", size_of(End_Central_Directory) + int(zip_file.end_of_directory.comment_length))

	fmt.println(">> OUT >> creating end central dir..")
	// END
	// copy header
	new_end : End_Central_Directory
	mem.copy(&new_end, &zip_file.end_of_directory, size_of(End_Central_Directory))
	new_end.size_dir = u32(pos + size_of(End_Central_Directory) + int(new_end.comment_length) - size_files)
	new_end.offset = u32(size_files)

	mem.copy(&output_buffer[pos], &new_end, size_of(End_Central_Directory))

	pos += size_of(End_Central_Directory)

	// copy comment
	if new_end.comment_length > 0 {
		copy(output_buffer[pos:], zip_file.comment)
	}

	pos += int(new_end.comment_length)

	output_file, _ := os.open(output_path, os.O_CREATE)
	os.write(output_file, output_buffer[:pos])
	os.close(output_file)
	fmt.println("file saved!")
}

// TODO implement
destroy_zip_file :: proc(archive:Zip_File) {
	// delete each inflated file.data []byte
	for file in archive.files { 
		delete(file.data)
	}
	// delete [dynamic]files
	delete(archive.files)
	// delete [dynamic]records
	delete(archive.records)
	// delete initial memory allocation for file
	delete(archive.buf)
}


