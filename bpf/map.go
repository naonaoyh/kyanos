package bpf

import (
	"reflect"

	"github.com/cilium/ebpf"
)

func GetMapFromObjs(objs any, mapName string) *ebpf.Map {
	val := reflect.ValueOf(objs)

	mapsField := val.Elem().Field(1)
	if !mapsField.IsValid() {
		return nil
	}
	mapSpecsVal := mapsField
	fieldName := mapName
	fieldVal := mapSpecsVal.FieldByName(fieldName)
	if fieldVal.IsValid() && fieldVal.Kind() == reflect.Ptr && !fieldVal.IsNil() {
		m := fieldVal.Interface().(*ebpf.Map)
		return m
	} else {
		return nil
	}
}
