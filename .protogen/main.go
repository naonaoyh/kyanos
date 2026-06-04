// Command protogen is an offline stand-in for `protoc`. It uses the pure-Go
// bufbuild/protocompile front-end to parse the .proto file and then drives the
// official protoc-gen-go / protoc-gen-go-grpc plugins over stdin/stdout exactly
// the way protoc does, producing authentic, protoc-equivalent generated code.
//
// Usage:
//   protogen <proto-file> <import-path> <plugin-exe> <plugin-param> <out-root>
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bufbuild/protocompile"
	"github.com/bufbuild/protocompile/linker"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: protogen <proto-file> <import-path> <plugin-exe> <plugin-param> <out-root>")
		os.Exit(2)
	}
	protoFile := os.Args[1]
	importPath := os.Args[2]
	pluginExe := os.Args[3]
	pluginParam := os.Args[4]
	outRoot := os.Args[5]

	if err := run(protoFile, importPath, pluginExe, pluginParam, outRoot); err != nil {
		fmt.Fprintln(os.Stderr, "protogen error:", err)
		os.Exit(1)
	}
}

func run(protoFile, importPath, pluginExe, pluginParam, outRoot string) error {
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			ImportPaths: []string{importPath},
		}),
		SourceInfoMode: protocompile.SourceInfoStandard,
	}

	files, err := compiler.Compile(context.Background(), protoFile)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	all := map[string]*descriptorpb.FileDescriptorProto{}
	var ordered []*descriptorpb.FileDescriptorProto
	for _, f := range files {
		collectFile(f, all, &ordered)
	}

	req := &pluginpb.CodeGeneratorRequest{
		FileToGenerate:  []string{protoFile},
		Parameter:       proto.String(pluginParam),
		ProtoFile:       ordered,
		CompilerVersion: &pluginpb.Version{Major: proto.Int32(5), Minor: proto.Int32(28), Patch: proto.Int32(0)},
	}

	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	cmd := exec.Command(pluginExe)
	cmd.Stdin = bytes.NewReader(reqBytes)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("plugin %s failed: %w: %s", pluginExe, err, errb.String())
	}

	resp := &pluginpb.CodeGeneratorResponse{}
	if err := proto.Unmarshal(out.Bytes(), resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	if resp.GetError() != "" {
		return fmt.Errorf("plugin reported error: %s", resp.GetError())
	}

	for _, gf := range resp.GetFile() {
		dst := filepath.Join(outRoot, gf.GetName())
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(gf.GetContent()), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", dst)
	}
	return nil
}

// collectFile appends a file descriptor and all its dependencies in
// dependency-first order, de-duplicating by path.
func collectFile(f linker.File, all map[string]*descriptorpb.FileDescriptorProto, ordered *[]*descriptorpb.FileDescriptorProto) {
	path := f.Path()
	if _, ok := all[path]; ok {
		return
	}
	// Recurse into imports first so dependencies appear before dependents.
	imports := f.Imports()
	for i := 0; i < imports.Len(); i++ {
		dep := imports.Get(i)
		if lf, ok := dep.FileDescriptor.(linker.File); ok {
			collectFile(lf, all, ordered)
		} else {
			collectDescriptor(dep.FileDescriptor, all, ordered)
		}
	}
	fdp := protodesc.ToFileDescriptorProto(f)
	all[path] = fdp
	*ordered = append(*ordered, fdp)
}

func collectDescriptor(fd protoreflect.FileDescriptor, all map[string]*descriptorpb.FileDescriptorProto, ordered *[]*descriptorpb.FileDescriptorProto) {
	path := fd.Path()
	if _, ok := all[path]; ok {
		return
	}
	imports := fd.Imports()
	for i := 0; i < imports.Len(); i++ {
		collectDescriptor(imports.Get(i).FileDescriptor, all, ordered)
	}
	fdp := protodesc.ToFileDescriptorProto(fd)
	all[path] = fdp
	*ordered = append(*ordered, fdp)
}
