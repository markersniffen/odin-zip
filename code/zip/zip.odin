package zip

import "core:os"
import "core:fmt"
import "core:mem"
import "core:hash"
import "core:bytes"
import "core:path/filepath"
import "core:compress/zlib"
import z "vendor:zlib"

LOCAL_FILE_SIGNATURE      :: 0x04034b50
CENTRAL_DIR_SIGNATURE     :: 0x02014b50
DIGITAL_SIGNATURE         :: 0x05054b50
END_CENTRAL_DIR_SIGNATURE :: 0x06054b50

Time :: u16
Date :: u16

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

Compression_Method :: enum u16 {
	None               = 0,
	Shrunk             = 1,
	Reduced_1          = 2,
	Reduced_2          = 3,
	Reduced_3          = 4,
	Reduced_4          = 5,
	Implode            = 6,
	Deflate            = 8,
	Enhanced_Deflate   = 9,
	PKWARE_Implode     = 10,
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
	Unknown                                         = 0x9902,
}

Local_File_Header :: struct #packed {
	signature:              u32,                // local file header signature     4 bytes
	version_needed:         u16,                // 2 bytes
	flags:                  bit_set[Flags],     // 2 bytes

	compression_method:     Compression_Method, // compression method              2 bytes
	last_mod_time:          Time,               // last mod file time              2 bytes
	last_mod_date:          Date,               // last mod file date              2 bytes

	crc32:                 u32,                 // crc-32                          4 bytes

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
	compression_method:  Compression_Method,
	last_mod_time:       Time,
	last_mod_date:       Date,
	crc32:              u32,
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

Zip_Error :: enum {
	SUCCESS,
	FAILED_TO_LOAD_FILE,
	FAILED_TO_FIND_HEADER,
	FAILED_TO_FIND_END_OF_FILE,
	DIGITAL_SIGNATURE_NOT_IMPLEMENTED,
}

Zip_File :: struct {
	data:                []byte,
	path:                string,
	files:               [dynamic]Local_File,
	records:             [dynamic]Central_Dir_Record,
	end_of_directory:    End_Central_Directory,
	comment:             string,
}

Local_File :: struct {
	name:                string,
	path:                string,
	ext:                 string,
	extra:               []byte,
	header:              Local_File_Header,
	compressed_data:     []byte,
	uncompressed_data:   []byte,
}

Central_Dir_Record :: struct {
	name:                string,
	path:                string,
	ext:                 string,
	comment:             string,
	extra:               []byte,
	header:              Central_Directory_Header,
}

End_Central_Directory :: struct #packed {	
	signature:                  u32, // 4 bytes  (0x06054b50)
	disk_number:                u16, // 2 bytes
	disk_width_central_dir:     u16, // 2 bytes
	num_entries_this_disk:      u16, // 2 bytes
	num_entries:				        u16, // 2 bytees
	size_dir:                   u32, // 4 bytes
	offset:                     u32, // 4 bytes
	comment_length:             u16, // 2 bytes
}

value_at_pos :: proc($T:typeid, data:[]byte, index:int=0) -> T {
	return ((^T)(&data[index]))^
}

read :: proc(path:string) -> (Zip_File, Zip_Error) {
	zip_file : Zip_File
	err: Zip_Error
	ok:bool

	// read file into memory
	zip_file.data, ok = os.read_entire_file(path)
	if !ok
	{
		return zip_file, .FAILED_TO_LOAD_FILE
	}
	
	zip_file.path = path
	
	scan := true
	pos: int = 0
	for scan {
		// signature : u32 = ((^u32)(&zip_file.data[pos]))^
		signature := value_at_pos(u32, zip_file.data, pos)

		switch signature {
			case LOCAL_FILE_SIGNATURE:
				header: Local_File_Header
				header = value_at_pos(Local_File_Header, zip_file.data, pos)
				// (cast(^Local_File_Header)(raw_data(zip_file.data[pos:])))^
				
				name_begin  := pos + size_of(Local_File_Header)
				name        := string(zip_file.data[name_begin:name_begin + int(header.file_name_length)])
				
				extra_begin := name_begin + len(name)
				extra       := zip_file.data[extra_begin:extra_begin + int(header.extra_field_length)]

				local_file: Local_File
				local_file.header   = header
				local_file.name     = filepath.base(name)
				local_file.ext      = filepath.ext(name)
				local_file.path = name
				local_file.extra    = extra

				// fmt.println(">> LOCAL FILE", name)

				raw_data_begin := extra_begin + int(header.extra_field_length)
				local_file.compressed_data = zip_file.data[raw_data_begin:raw_data_begin + int(header.compressed_size)]
				
				inflate_file(&local_file)

				append(&zip_file.files, local_file)
				pos += size_of(Local_File_Header) + int(header.file_name_length) + int(header.extra_field_length) + int(header.compressed_size)

			case CENTRAL_DIR_SIGNATURE:
				header:    Central_Directory_Header
				header   = value_at_pos(Central_Directory_Header, zip_file.data, pos)
				// header   = (cast(^Central_Directory_Header)(raw_data(zip_file.data[pos:])))^

				name_begin  := pos + size_of(Central_Directory_Header)
				name        := string(zip_file.data[name_begin:name_begin + int(header.file_name_length)])
				
				extra_begin := name_begin + int(header.file_name_length)
				extra       := zip_file.data[extra_begin:extra_begin + int(header.extra_field_length)]

				comment_begin := pos + size_of(Central_Directory_Header) + int(header.file_name_length) + int(header.extra_field_length)
				comment     := string(zip_file.data[comment_begin:comment_begin + int(header.file_comment_length)])
				
				record: Central_Dir_Record
				record.header    = header
				record.name      = filepath.base(name)
				record.ext       = filepath.ext(name)
				record.path  = name
				record.extra     = extra
				record.comment   = comment

				// fmt.println(">> CENTRAL DIR RECORD", name)
				append(&zip_file.records, record)
				pos += size_of(Central_Directory_Header) + int(header.file_name_length) + int(header.extra_field_length) + int(header.file_comment_length)

			case DIGITAL_SIGNATURE:
				fmt.println("Digitial Signature not implemented...")
				return {}, .DIGITAL_SIGNATURE_NOT_IMPLEMENTED

			case END_CENTRAL_DIR_SIGNATURE:
				scan = false
				// fmt.println(">> END CENTRAL DIR")

				zip_file.end_of_directory = value_at_pos(End_Central_Directory, zip_file.data, pos)
				// zip_file.end_of_directory = (cast(^End_Central_Directory)(raw_data(zip_file.data[pos:])))^
				pos += size_of(End_Central_Directory)
				comment_length := int(zip_file.end_of_directory.comment_length)

				if comment_length > 0 {
					zip_file.comment = string(zip_file.data[pos:pos+comment_length])
				} else {
					zip_file.comment = ""
				}

				pos += comment_length
			case: 
				fmt.println("Failed to find a header at", pos)
				return {}, .FAILED_TO_FIND_HEADER
		}
	}

	return zip_file, .SUCCESS
}

inflate_file :: proc(file:^Local_File) {
	buf: bytes.Buffer
	defer bytes.buffer_destroy(&buf)
	#partial switch file.header.compression_method {
		case .Deflate:
			// fmt.println(">> from file raw size <<", len(file.raw_data))
			// fmt.println("uncompressed_size", file.name, ":", file.header.uncompressed_size)
			err := zlib.inflate(input=file.compressed_data, buf=&buf, expected_output_size=int(file.header.uncompressed_size), raw=true)
			if err != nil {
				fmt.printf("\nInflate Error: %v\n", err)
			} else {
				file.uncompressed_data = make([]byte, len(buf.buf))
				copy_slice(file.uncompressed_data, buf.buf[:])
			}
			crc := hash.crc32(file.uncompressed_data)
			assert(crc == file.header.crc32)
			// fmt.println("buf size", len(buf.buf))
		case .None:
			file.uncompressed_data = make([]byte, len(file.compressed_data))
			copy(file.uncompressed_data, file.compressed_data)
		case:
			assert(0!=0, "only works with deflate or no compression...")
	}
}

compress_stream :: proc(input_data:[]byte) -> []byte {
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
	if err < 0 do assert(false)
	
	// TODO this isn't right
	// res := OK
	// for res != STREAM_END {
	res := deflate(&strm, FINISH)
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

create_zip :: proc(path:string, comment:string="") -> Zip_File {
	new_zip: Zip_File
	new_zip.path = path
	new_zip.comment = comment
	return new_zip
}

// TODO implement
destroy_zip :: proc(archive:Zip_File) {
	// delete each inflated file.data []byte
	for file in archive.files { 
		delete(file.uncompressed_data)
	}
	// delete [dynamic]files
	delete(archive.files)
	// delete [dynamic]records
	delete(archive.records)
	// delete initial memory allocation for file
	delete(archive.data)
}

add_to_zip :: proc(zip_file:^Zip_File, path:string, data:[]byte, compression_method:Compression_Method=.Deflate, extra:[]byte=nil, comment:string="") {
	local_file: Local_File
	local_file.name                      = filepath.base(path)
	local_file.ext                       = filepath.ext(path)
	local_file.path                      = path
	local_file.extra                     = extra
	local_file.uncompressed_data         = data
	local_file.header.compression_method = compression_method
	
	append(&zip_file.files, local_file)

	record: Central_Dir_Record
	record.name                      = local_file.name
	record.ext                       = local_file.ext
	record.path                      = path
	record.extra                     = extra
	record.comment                   = comment
	record.header.compression_method = compression_method

	append(&zip_file.records, record)
}

zip :: proc(zip_file:^Zip_File, path:string, comment:string="") {
	zip_file.comment = comment

	// alloc mem
	output_buffer: [dynamic]byte
	defer delete(output_buffer)
	
	num_files := len(zip_file.files)
	reserve(&output_buffer, num_files*( len(zip_file.files[0].uncompressed_data) / 2 ) )
	dest_sizes := make([]u32, num_files)
	defer delete(dest_sizes)
	offsets := make([]u32, num_files)
	defer delete(offsets)

	pos:int
	for file, fi in &zip_file.files
	{
		file.header.file_name_length = u16(len(file.path))
		file.header.signature            = LOCAL_FILE_SIGNATURE
		file.header.version_needed       = 20
		file.header.flags                = {.compression_option_a, .compression_option_b}
		//file.header.compression_method  TODO already filled out
		file.header.last_mod_time        = 0
		file.header.last_mod_date        = 0
		file.header.crc32                = hash.crc32(file.uncompressed_data)
		file.header.compressed_size      = 0
		file.header.uncompressed_size    = u32(len(file.uncompressed_data))
		file.header.file_name_length     = u16(len(file.path))
		file.header.extra_field_length   = u16(len(file.extra))

		#partial switch file.header.compression_method {
			case .Deflate:
				// TODO use stream or not?
				// file.compressed_data = compress(uncompressed_data)
				file.compressed_data = compress_stream(file.uncompressed_data)
				file.header.compressed_size = u32(len(file.compressed_data))
			case .None:
				file.compressed_data = file.uncompressed_data
				file.header.compressed_size = u32(len(file.compressed_data))
			case:
				assert(0 != 0, "Only supports Deflate or None..")
		}

		dest_sizes[fi] = file.header.compressed_size
		name_len := file.header.file_name_length
		extra_len := file.header.extra_field_length

		offsets[fi] = u32(pos)

		// resize file buffer if need be
		end := pos + size_of(Local_File_Header) + int(name_len) + int(extra_len) + int(file.header.compressed_size)
		if end > len(output_buffer) do resize(&output_buffer, end + 4)

		// copy header struct
		mem.copy(&output_buffer[pos], &file.header, size_of(Local_File_Header))
		pos += size_of(Local_File_Header)

		// copy file name
		copy(output_buffer[pos:], file.path)
		pos += int(file.header.file_name_length)
		
		// copy extra
		copy(output_buffer[pos:], file.extra)
		pos += int(file.header.extra_field_length)

		copy(output_buffer[pos:], file.compressed_data)
		pos += int(file.header.compressed_size)
	}

	size_files := pos

	// RECORDS
	for record, ri in &zip_file.records {
		// fmt.println(">> OUT >> Zipping record", record.name)
		dest_len := dest_sizes[ri]
		offset   := offsets[ri]
		new_header: Central_Directory_Header
		local_file := zip_file.files[ri]
		header := local_file.header
		
		// header stuff
		new_header.signature           = CENTRAL_DIR_SIGNATURE
		new_header.version             = header.version_needed  // TODO ??
		new_header.version_needed      = header.version_needed  // TODO ??
		new_header.flags               = header.flags // TODO 
		new_header.compression_method  = header.compression_method
		new_header.last_mod_time       = header.last_mod_time
		new_header.last_mod_date       = header.last_mod_date
		new_header.crc32               = header.crc32
		new_header.compressed_size     = header.compressed_size
		new_header.uncompressed_size   = header.uncompressed_size
		new_header.file_name_length    = header.file_name_length
		new_header.extra_field_length  = header.extra_field_length
		new_header.file_comment_length = u16(len(record.comment))
		new_header.disk_number_start   = 0
		new_header.internal_attribute  = 0
		new_header.external_attribute  = 0
		new_header.offset_local_header = offset

		record.header = new_header

		mem.copy(&new_header, &record.header, size_of(Central_Directory_Header))

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
	
		// copy file path
		copy(output_buffer[pos:], record.path)
		assert(int(new_header.file_name_length) == len(record.path))
		pos += len(record.path)

		// copy extra field
		mem.copy(&output_buffer[pos], &record.extra, int(new_header.extra_field_length))
		pos += int(new_header.extra_field_length)

		// copy comment
		if comment_len > 0 {
			mem.copy(&output_buffer[pos], &record.comment, int(comment_len))
		}
		pos += int(comment_len)
	}

	end : End_Central_Directory
	end.signature              = END_CENTRAL_DIR_SIGNATURE
	end.disk_number            = 0
	end.disk_width_central_dir = 0
	end.num_entries_this_disk  = u16(len(zip_file.files))
	end.num_entries				     = u16(len(zip_file.files))
	end.size_dir               = u32(pos - size_files)
	end.offset                 = u32(size_files)
	end.comment_length         = u16(len(comment))
	zip_file.end_of_directory = end

	// END
	if len(output_buffer) < pos + size_of(End_Central_Directory) + int(zip_file.end_of_directory.comment_length) {
		resize(&output_buffer, pos + size_of(End_Central_Directory) + int(zip_file.end_of_directory.comment_length))
	}


	// copy header
	mem.copy(&output_buffer[pos], &end, size_of(End_Central_Directory))
	pos += size_of(End_Central_Directory)

	// copy comment
	if end.comment_length > 0 {
		copy(output_buffer[pos:], zip_file.comment)
	}

	pos += int(end.comment_length)
	
	output_file, _ := os.open(path, os.O_CREATE)
	os.write(output_file, output_buffer[:pos])
	os.close(output_file)
	fmt.println("file saved!")
}

// assumes you just have changed local_file.data and rezips
zip_deflate :: proc(zip_file: ^Zip_File, input_files_data:[][]byte, output_path:string) {
	// fmt.println(">> OUT >> Starting to deflate and zip:", zip_file.path, ">>", output_path)

	// alloc mem
	output_buffer: [dynamic]byte
	defer delete(output_buffer)
	reserve(&output_buffer, len(zip_file.data))
	dest_sizes := make([]u32, len(zip_file.files))
	defer delete(dest_sizes)
	offsets := make([]u32, len(zip_file.files))
	defer delete(offsets)

	pos:int
	// output each file_header & file data, compress if necessary
	for file, fi in &zip_file.files {
		pos_at_start := pos
		offsets[fi] = u32(pos)

		new_header: Local_File_Header
		mem.copy(&new_header, &file.header, size_of(Local_File_Header))

		raw_data := input_files_data[fi]

		compressed_file_data: []byte
		defer delete(compressed_file_data)
		
		#partial switch file.header.compression_method {
			case .Deflate:
				// compressed_file_data = compress(raw_data)
				compressed_file_data = compress_stream(raw_data)
				new_header.compressed_size = u32(len(compressed_file_data))
				
				// fmt.println("deflating size", new_header.compressed_size, len(compressed_file_data))

				// compressed_file_data = raw_data
				// new_header.compressed_size = u32(len(raw_data))
				// new_header.compression_method = .None
			case .None:
				compressed_file_data = raw_data
				new_header.compressed_size = u32(len(raw_data))
			case:
				assert(0 != 0, "Only supports Deflate or no compression..")
		}


		assert(compressed_file_data != nil)
		assert(!(.data_descriptor in new_header.flags))

		dest_sizes[fi] = new_header.compressed_size
		name_len := new_header.file_name_length
		extra_len := new_header.extra_field_length

		// resize file buffer if need be
		end := pos + size_of(Local_File_Header) + int(name_len) + int(extra_len) + int(new_header.compressed_size)
		if end > len(output_buffer) do resize(&output_buffer, end + 4)

		// copy header struct
		mem.copy(&output_buffer[pos], &new_header, size_of(Local_File_Header))
		pos += size_of(Local_File_Header)

		// copy file name
		copy(output_buffer[pos:], file.path)
		pos += int(new_header.file_name_length)
		
		// copy extra
		copy(output_buffer[pos:], file.extra)
		// fmt.printf("%x\n", file.extra )
		// fmt.printf("%x\n", output_buffer[pos:new_header.extra_field_length] )
		pos += int(new_header.extra_field_length)

		copy(output_buffer[pos:], compressed_file_data)
		pos += int(new_header.compressed_size)


		// fmt.printf("%v, %x\n", file.name, output_buffer[pos_at_start:pos] )
		assert(len(compressed_file_data) == int(new_header.compressed_size))
		assert(len(file.path) == int(new_header.file_name_length))
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
	
		// copy file path
		copy(output_buffer[pos:], record.path)
		assert(int(new_header.file_name_length) == len(record.path))
		pos += len(record.path)

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

	fmt.println(">> OUT >> creating end central dir..")
	// END
	// copy header
	new_end : End_Central_Directory
	mem.copy(&new_end, &zip_file.end_of_directory, size_of(End_Central_Directory))
	new_end.size_dir = u32(pos - size_files)
	// new_end.size_dir = u32(pos + size_of(End_Central_Directory) + int(new_end.comment_length) - size_files)
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