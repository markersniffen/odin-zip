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
	// app.path = "X:/dev/zip/assets/output.zip"
	// app.path = "X:/dev/zip/assets/files.zip"
	app.path = "X:/dev/zip/assets/tiny.pptx"
	out     := "X:/dev/zip/assets/output.pptx"
	
	zip_file, err := read(app.path)
	if err != nil { fmt.println(err) }


	for file in &zip_file.files {
		for ci := 0; ci < len(file.uncompressed_data)-4; ci += 1 {
			if string(file.uncompressed_data[ci:ci+4]) == "Mark" {
				str := "Dave"
				copy(file.uncompressed_data[ci:], transmute([]byte)(str))
			}
		}
	}

	new_zip := create_zip(out)

	for file in zip_file.files {
		add_to_zip(&new_zip, file.path, file.uncompressed_data)
	}

	zip(&new_zip, out)

	// new_zip := create_zip("X:/dev/zip/assets/generated_zip_file.zip")

	// readme := "This is the reade file"
	// readme_path := "home/readme.txt"
	// readme_data := transmute([]u8)readme
	// add_to_zip(&new_zip, readme_path, readme_data, .Deflate)

	// content := "File two has more text in it and is a tad longer."
	// data := transmute([]u8)content
	// path := "home/content.txt"
	// add_to_zip(&new_zip, path, data, .Deflate)


	// zip(new_zip, new_zip.path, "First exported zip file!")


	// zip(file_data, file_names, out)
	// zip_deflate(&zip_file, file_data, out)
}
