//go:build js && wasm

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall/js"
	"time"

	"github.com/microsoft/TypeScript/tsc/internal/api/encoder"
	"github.com/microsoft/TypeScript/tsc/internal/ast"
	"github.com/microsoft/TypeScript/tsc/internal/core"
	"github.com/microsoft/TypeScript/tsc/internal/json"
	"github.com/microsoft/TypeScript/tsc/internal/locale"
	"github.com/microsoft/TypeScript/tsc/internal/parser"
	"github.com/microsoft/TypeScript/tsc/internal/tsoptions"
	"github.com/microsoft/TypeScript/tsc/internal/tspath"
	"github.com/microsoft/TypeScript/tsc/internal/vfs"
)

type diagnostic struct {
	FileName    string `json:"fileName,omitzero"`
	Start       *int   `json:"start,omitzero"`
	Length      *int   `json:"length,omitzero"`
	Code        int32  `json:"code"`
	Category    int    `json:"category"`
	MessageText string `json:"messageText"`
}

type config struct {
	FileNames []string              `json:"fileNames"`
	Options   *core.CompilerOptions `json:"options"`
	Raw       any                   `json:"raw,omitzero"`
	Errors    []diagnostic          `json:"errors"`
}

func convert(items []*ast.Diagnostic) []diagnostic {
	result := make([]diagnostic, 0, len(items))
	for _, item := range items {
		converted := diagnostic{
			Code:        item.Code(),
			Category:    int(item.Category()),
			MessageText: item.Localize(locale.Default),
		}
		if file := item.File(); file != nil {
			size := len(file.Text())
			pos := max(0, min(item.Pos(), size))
			end := max(pos, min(item.End(), size))
			positions := file.GetPositionMap()
			start := positions.UTF8ToUTF16(pos)
			length := positions.UTF8ToUTF16(end) - start
			converted.FileName = file.FileName()
			converted.Start = &start
			converted.Length = &length
		}
		result = append(result, converted)
	}
	return result
}

func parse(fileName string, text string, kind core.ScriptKind, cwd string) (map[string]any, error) {
	if kind == core.ScriptKindUnknown {
		kind = core.EnsureScriptKindFromFileName(fileName)
	}
	switch kind {
	case core.ScriptKindJS, core.ScriptKindJSX, core.ScriptKindTS, core.ScriptKindTSX, core.ScriptKindJSON:
	default:
		return nil, fmt.Errorf("invalid scriptKind %d", kind)
	}
	fileName = tspath.GetNormalizedAbsolutePath(fileName, cwd)
	file := parser.ParseSourceFile(ast.SourceFileParseOptions{
		FileName: fileName,
		Path:     tspath.Path(fileName),
	}, text, kind)
	data, _, err := encoder.EncodeSourceFile(file)
	if err != nil {
		return nil, err
	}
	diagnostics, err := json.Marshal(convert(file.Diagnostics()))
	if err != nil {
		return nil, err
	}
	bytes := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(bytes, data)
	return map[string]any{"data": bytes, "diagnostics": string(diagnostics)}, nil
}

func toObject(fileName string, text string, cwd string) (map[string]any, error) {
	fileName = tspath.GetNormalizedAbsolutePath(fileName, cwd)
	value, errs := tsoptions.ParseConfigFileTextToJson(fileName, tspath.Path(fileName), text)
	object, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	diagnostics, err := json.Marshal(convert(errs))
	if err != nil {
		return nil, err
	}
	return map[string]any{"value": string(object), "diagnostics": string(diagnostics)}, nil
}

type hostFS struct {
	host js.Value
}

func (f hostFS) has(name string) bool {
	return f.host.Get(name).Type() == js.TypeFunction
}

func (f hostFS) UseCaseSensitiveFileNames() bool {
	if f.has("useCaseSensitiveFileNames") {
		return f.host.Call("useCaseSensitiveFileNames").Truthy()
	}
	return f.host.Get("useCaseSensitiveFileNames").Truthy()
}

func (f hostFS) FileExists(path string) bool {
	return f.host.Call("fileExists", path).Truthy()
}

func (f hostFS) ReadFile(path string) (string, bool) {
	value := f.host.Call("readFile", path)
	if value.Type() != js.TypeObject {
		return "", false
	}
	return wtf8(value), true
}

func (f hostFS) DirectoryExists(path string) bool {
	if !f.has("directoryExists") {
		return true
	}
	return f.host.Call("directoryExists", path).Truthy()
}

func (f hostFS) Realpath(path string) string {
	if !f.has("realpath") {
		return path
	}
	return f.host.Call("realpath", path).String()
}

func stringArray(value js.Value) []string {
	if value.Type() != js.TypeObject {
		return nil
	}
	result := make([]string, value.Length())
	for i := range result {
		result[i] = value.Index(i).String()
	}
	return result
}

func (f hostFS) GetAccessibleEntries(path string) vfs.Entries {
	if !f.has("getAccessibleFileSystemEntries") {
		return vfs.Entries{}
	}
	entries := f.host.Call("getAccessibleFileSystemEntries", path)
	return vfs.Entries{
		Files:       stringArray(entries.Get("files")),
		Directories: stringArray(entries.Get("directories")),
	}
}

func (f hostFS) Stat(path string) vfs.FileInfo {
	return nil
}

func (f hostFS) WriteFile(path string, data string) error {
	return errors.ErrUnsupported
}

func (f hostFS) AppendFile(path string, data string) error {
	return errors.ErrUnsupported
}

func (f hostFS) Remove(path string) error {
	return errors.ErrUnsupported
}

func (f hostFS) Chtimes(path string, aTime time.Time, mTime time.Time) error {
	return errors.ErrUnsupported
}

type configHost struct {
	fs  hostFS
	cwd string
}

func (h configHost) FS() vfs.FS {
	return h.fs
}

func (h configHost) GetCurrentDirectory() string {
	return h.cwd
}

func parseConfig(fileName string, text string, basePath string, configFileName string, host js.Value) (map[string]any, error) {
	fs := hostFS{host: host}
	cwd := basePath
	if fs.has("getCurrentDirectory") {
		cwd = host.Call("getCurrentDirectory").String()
	}
	fileName = tspath.GetNormalizedAbsolutePath(fileName, cwd)
	source := tsoptions.NewTsconfigSourceFileFromFilePath(
		fileName,
		tspath.ToPath(fileName, cwd, fs.UseCaseSensitiveFileNames()),
		text,
	)
	parsed := tsoptions.ParseJsonSourceFileConfigFileContent(source, configHost{fs: fs, cwd: cwd}, basePath, nil, nil, configFileName, nil, nil)
	value, err := json.Marshal(config{
		FileNames: parsed.FileNames(),
		Options:   parsed.CompilerOptions(),
		Raw:       parsed.Raw,
		Errors:    convert(parsed.Errors),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"value": string(value)}, nil
}

func wtf8(value js.Value) string {
	data := make([]byte, value.Length())
	js.CopyBytesToGo(data, value)
	return string(data)
}

func export(fn func(args []js.Value) (map[string]any, error)) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) (result any) {
		defer func() {
			if recovered := recover(); recovered != nil {
				result = map[string]any{"error": fmt.Sprint(recovered)}
			}
		}()
		value, err := fn(args)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return value
	})
}

func main() {
	name := os.Getenv("TSC_COMPAT_GLOBAL")
	if name == "" {
		name = "tscCompat"
	}
	js.Global().Set(name, map[string]any{
		"parse": export(func(args []js.Value) (map[string]any, error) {
			return parse(args[0].String(), wtf8(args[1]), core.ScriptKind(args[2].Int()), args[3].String())
		}),
		"toObject": export(func(args []js.Value) (map[string]any, error) {
			return toObject(args[0].String(), wtf8(args[1]), args[2].String())
		}),
		"parseConfig": export(func(args []js.Value) (map[string]any, error) {
			return parseConfig(args[0].String(), wtf8(args[1]), args[2].String(), args[3].String(), args[4])
		}),
	})
	select {}
}
