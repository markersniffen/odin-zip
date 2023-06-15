package main	

import "./zip"
import "core:fmt"

print :: proc(args:..any) { fmt.println(..args) }

App :: struct {
	path: string,
}

app : App

main :: proc() {
	using zip
	app.path = "X:/dev/zip/assets/output.zip"
	app.path = "X:/dev/zip/assets/files.zip"
	app.path = "X:/dev/zip/assets/tiny.pptx"
	out     := "X:/dev/zip/assets/output.zip"
	zip_file: Zip_File
	zip_file = read(app.path)

	
	file_data := make([][]byte, len(zip_file.files))
	for file, fi in zip_file.files {
		// print("file name len", file.header.file_name_length, "file name", file.name)
		// print("file extra len", file.header.extra_field_length, "file extra", file.extra)
		assert(u16(len(file.fullname)) == file.header.file_name_length)
		assert(u16(len(file.extra)) == file.header.extra_field_length)
		file_data[fi] = file.data
	}

	zip_deflate(&zip_file, file_data, out)
}
