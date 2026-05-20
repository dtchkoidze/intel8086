package main
import "core:os"
import "core:log"
import "core:path/filepath"
import "core:strings"

find_executable :: proc(name: string) -> (string, bool) {
	path_env, ok := os.lookup_env_alloc("PATH", context.allocator)
	if !ok do return "", false

	dirs := strings.split(path_env, ":")
	defer delete(dirs)

	for dir in dirs {
		full, err := filepath.join({dir, name}, context.allocator)
		if err != nil do return "", false
		if os.exists(full) {
			stat, err := os.stat(full, context.allocator)
			defer os.file_info_delete(stat, context.allocator)
			if err != nil do return "", false
			is_exec := os.Permissions_Execute_All & stat.mode != {}
			if is_exec {
				return full, true
			}
		}
		delete(full)
	}
	return "", false
}


compile :: proc(filename: string) -> ([]byte, bool) {
	data, err := os.read_entire_file(filename, context.allocator)
	if err != nil {
		log.errorf("failed to read file %v", err)
		return []byte{}, false
	}
	defer delete(data)

	nasmexe, oknasm := find_executable("nasm")
	if !oknasm {
		log.errorf("failed to find nasm executable on machine")
		return []byte{}, false
	}

	binf := strings.join([]string{"/tmp/", filename, ".bin"}, "", context.allocator)

	command := []string{nasmexe, "-f", "bin", filename, "-o", binf}
	process, perr := os.process_start({command = command, stdout = os.stdout, stderr = os.stderr})
	if perr != nil {
		log.error(perr)
		return []byte{}, false
	}
	s, werr := os.process_wait(process)
	if werr != nil {
		kerr := os.process_kill(process)
		if kerr != nil {
			return []byte{}, false
		}
		return []byte{}, false
	}

	bdata, berr := os.read_entire_file(binf, context.allocator)
	if berr != nil {
		log.errorf("failed to read binary file: %v", err)
		return []byte{}, false
	}

	return bdata, true
}


disass :: proc() {

}

as :: proc() {

}
