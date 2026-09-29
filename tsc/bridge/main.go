// A small JSON-lines bridge to a pinned TypeScript Go compiler.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/microsoft/TypeScript/tsc/internal/ast"
	"github.com/microsoft/TypeScript/tsc/internal/bundled"
	"github.com/microsoft/TypeScript/tsc/internal/checker"
	"github.com/microsoft/TypeScript/tsc/internal/compiler"
	"github.com/microsoft/TypeScript/tsc/internal/core"
	"github.com/microsoft/TypeScript/tsc/internal/locale"
	"github.com/microsoft/TypeScript/tsc/internal/transpile"
	"github.com/microsoft/TypeScript/tsc/internal/tsoptions"
	"github.com/microsoft/TypeScript/tsc/internal/vfs/osvfs"
)

type request struct {
	ID          uint64   `json:"id"`
	Method      string   `json:"method"`
	Source      string   `json:"source"`
	FileName    string   `json:"fileName"`
	ConfigPath  string   `json:"configPath"`
	Entrypoints []string `json:"entrypoints"`
}

type diagnostic struct {
	Code     int32        `json:"code"`
	Category int          `json:"category"`
	Message  string       `json:"message"`
	FileName string       `json:"fileName,omitempty"`
	Start    int          `json:"start"`
	Length   int          `json:"length"`
	Children []diagnostic `json:"children,omitempty"`
}

type codeUnion struct {
	Name  string   `json:"name"`
	Codes []string `json:"codes"`
}

type response struct {
	ID          uint64       `json:"id"`
	Error       string       `json:"error,omitempty"`
	OutputText  string       `json:"outputText"`
	Diagnostics []diagnostic `json:"diagnostics"`
	Unions      []codeUnion  `json:"unions"`
}

func diagnostics(items []*ast.Diagnostic) []diagnostic {
	result := make([]diagnostic, 0, len(items))
	for _, item := range items {
		d := diagnostic{
			Code: item.Code(), Category: int(item.Category()),
			Message: item.Localize(locale.Default), Start: item.Pos(), Length: item.Len(),
			Children: diagnostics(item.MessageChain()),
		}
		if item.File() != nil {
			d.FileName = item.File().FileName()
		}
		result = append(result, d)
	}
	return result
}

func loadProgram(configPath string) (*compiler.Program, []*ast.Diagnostic, error) {
	if configPath == "" {
		return nil, nil, errors.New("configPath is required")
	}
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, nil, err
	}
	host := compiler.NewCompilerHost(
		filepath.Dir(configPath), bundled.WrapFS(osvfs.FS()), bundled.LibPath(), nil, nil, nil,
	)
	config, parseErrors := tsoptions.GetParsedCommandLineOfConfigFile(
		filepath.ToSlash(configPath), &core.CompilerOptions{NoEmit: core.TSTrue}, nil, host, nil,
	)
	if config == nil || len(parseErrors) != 0 {
		return nil, parseErrors, nil
	}
	// Each request reads a fresh project; no stale source or configuration cache.
	return compiler.NewProgram(compiler.ProgramOptions{
		ProgramConfig: compiler.ProgramConfig{Config: config, SingleThreaded: core.TSTrue},
		ProgramHosts:  compiler.ProgramHosts{Host: host},
	}), nil, nil
}

func collectCodeUnions(ctx context.Context, program *compiler.Program, req request) ([]codeUnion, error) {
	if len(req.Entrypoints) == 0 {
		return nil, errors.New("entrypoints must not be empty")
	}
	program.BindSourceFiles()
	c, release := program.GetTypeChecker(ctx)
	defer release()
	byName := make(map[string][]string)
	for _, entry := range req.Entrypoints {
		if !filepath.IsAbs(entry) {
			entry = filepath.Join(filepath.Dir(req.ConfigPath), entry)
		}
		absolute, err := filepath.Abs(entry)
		if err != nil {
			return nil, err
		}
		source := program.GetSourceFile(filepath.ToSlash(absolute))
		if source == nil {
			return nil, fmt.Errorf("entrypoint is not in the project: %s", entry)
		}
		module := c.GetSymbolAtLocation(source.AsNode())
		if module == nil {
			return nil, fmt.Errorf("entrypoint is not a module: %s", entry)
		}
		for _, exported := range c.GetExportsOfModule(module) {
			name := exported.Name
			if !strings.HasSuffix(name, "ErrorCode") && !strings.HasSuffix(name, "ReasonCode") {
				continue
			}
			symbol := exported
			if symbol.Flags&ast.SymbolFlagsAlias != 0 {
				symbol = c.GetAliasedSymbol(symbol)
			}
			declared := c.GetDeclaredTypeOfSymbol(symbol)
			parts := []*checker.Type{declared}
			if declared.Flags()&checker.TypeFlagsUnion != 0 {
				parts = declared.Types()
			}
			codes := make([]string, 0, len(parts))
			for _, part := range parts {
				if part.Flags()&checker.TypeFlagsStringLiteral != 0 {
					if value, ok := part.AsLiteralType().Value().(string); ok {
						codes = append(codes, value)
					}
				}
			}
			if len(codes) == 0 {
				continue
			}
			slices.Sort(codes)
			codes = slices.Compact(codes)
			if previous, exists := byName[name]; exists && !slices.Equal(previous, codes) {
				return nil, fmt.Errorf("conflicting exported unions named %s", name)
			}
			byName[name] = codes
		}
	}
	result := make([]codeUnion, 0, len(byName))
	for name, codes := range byName {
		result = append(result, codeUnion{Name: name, Codes: codes})
	}
	slices.SortFunc(result, func(a, b codeUnion) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}

func handle(req request) response {
	result := response{ID: req.ID, Diagnostics: []diagnostic{}, Unions: []codeUnion{}}
	ctx := context.Background()
	if req.Method == "transpile" {
		output := transpile.TranspileModule(ctx, req.Source, transpile.Options{
			FileName: req.FileName, ReportDiagnostics: true,
			CompilerOptions: &core.CompilerOptions{Target: core.ScriptTargetESNext, Module: core.ModuleKindESNext},
		})
		if output == nil {
			result.Error = "transpilation canceled"
			return result
		}
		result.OutputText = output.OutputText
		result.Diagnostics = diagnostics(output.Diagnostics)
		return result
	}
	if req.Method != "checkProject" && req.Method != "exportedCodeUnions" {
		result.Error = fmt.Sprintf("unknown method: %s", req.Method)
		return result
	}
	program, parseErrors, err := loadProgram(req.ConfigPath)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if program == nil {
		result.Diagnostics = diagnostics(parseErrors)
		if req.Method == "exportedCodeUnions" {
			result.Error = "cannot extract unions from an invalid project configuration"
		}
		return result
	}
	if req.Method == "exportedCodeUnions" {
		result.Unions, err = collectCodeUnions(ctx, program, req)
		if err != nil {
			result.Error = err.Error()
		}
		return result
	}
	items := program.GetConfigFileParsingDiagnostics()
	items = append(items, program.GetProgramDiagnostics()...)
	items = append(items, program.GetSyntacticDiagnostics(ctx, nil)...)
	items = append(items, program.GetGlobalDiagnostics(ctx)...)
	items = append(items, program.GetSemanticDiagnostics(ctx, nil)...)
	slices.SortFunc(items, ast.CompareDiagnostics)
	result.Diagnostics = diagnostics(slices.CompactFunc(items, ast.EqualDiagnostics))
	return result
}

func run(in io.Reader, out io.Writer) error {
	decoder, encoder := json.NewDecoder(in), json.NewEncoder(out)
	for {
		var req request
		if err := decoder.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode request: %w", err)
		}
		if err := encoder.Encode(handle(req)); err != nil {
			return err
		}
	}
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
