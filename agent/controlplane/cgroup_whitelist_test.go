package controlplane

import (
	"errors"
	"reflect"
	"testing"
)

func TestReconcileCgroups_AddAndRemove(t *testing.T) {
	current := CgroupSetFromSlice([]uint64{1, 2, 3})
	add := CgroupSetFromSlice([]uint64{3, 4, 5})
	remove := CgroupSetFromSlice([]uint64{2})

	diff := ReconcileCgroups(current, add, remove)

	// Desired = ({1,2,3} ∪ {3,4,5}) \ {2} = {1,3,4,5}
	wantDesired := CgroupSetFromSlice([]uint64{1, 3, 4, 5})
	if !reflect.DeepEqual(diff.Desired, wantDesired) {
		t.Errorf("Desired = %v, want %v", diff.Desired, wantDesired)
	}
	// ToAdd = desired \ current = {4,5}
	if want := []uint64{4, 5}; !reflect.DeepEqual(diff.ToAdd, want) {
		t.Errorf("ToAdd = %v, want %v", diff.ToAdd, want)
	}
	// ToDelete = current \ desired = {2}
	if want := []uint64{2}; !reflect.DeepEqual(diff.ToDelete, want) {
		t.Errorf("ToDelete = %v, want %v", diff.ToDelete, want)
	}
}

func TestReconcileCgroups_RemoveTakesPrecedenceOverAdd(t *testing.T) {
	current := CgroupSetFromSlice([]uint64{1})
	add := CgroupSetFromSlice([]uint64{2})
	remove := CgroupSetFromSlice([]uint64{2})

	diff := ReconcileCgroups(current, add, remove)

	// 2 is both added and removed; remove is applied last -> excluded.
	if _, ok := diff.Desired[2]; ok {
		t.Errorf("Desired should not contain 2, got %v", diff.Desired)
	}
	if want := CgroupSetFromSlice([]uint64{1}); !reflect.DeepEqual(diff.Desired, want) {
		t.Errorf("Desired = %v, want %v", diff.Desired, want)
	}
	if len(diff.ToAdd) != 0 {
		t.Errorf("ToAdd = %v, want empty", diff.ToAdd)
	}
	if len(diff.ToDelete) != 0 {
		t.Errorf("ToDelete = %v, want empty", diff.ToDelete)
	}
}

func TestReconcileCgroups_NilInputs(t *testing.T) {
	diff := ReconcileCgroups(nil, nil, nil)
	if len(diff.Desired) != 0 {
		t.Errorf("Desired = %v, want empty", diff.Desired)
	}
	if diff.ToAdd != nil {
		t.Errorf("ToAdd = %v, want nil", diff.ToAdd)
	}
	if diff.ToDelete != nil {
		t.Errorf("ToDelete = %v, want nil", diff.ToDelete)
	}
}

func TestReconcileCgroups_NoChangeIsMinimal(t *testing.T) {
	current := CgroupSetFromSlice([]uint64{10, 20, 30})
	// add an id that is already present; remove nothing.
	diff := ReconcileCgroups(current, CgroupSetFromSlice([]uint64{20}), nil)

	if len(diff.ToAdd) != 0 {
		t.Errorf("ToAdd = %v, want empty (no new ids)", diff.ToAdd)
	}
	if len(diff.ToDelete) != 0 {
		t.Errorf("ToDelete = %v, want empty (nothing removed)", diff.ToDelete)
	}
}

func TestReconcileCgroups_DoesNotMutateInputs(t *testing.T) {
	current := CgroupSetFromSlice([]uint64{1, 2})
	add := CgroupSetFromSlice([]uint64{3})
	remove := CgroupSetFromSlice([]uint64{1})

	_ = ReconcileCgroups(current, add, remove)

	if !reflect.DeepEqual(current, CgroupSetFromSlice([]uint64{1, 2})) {
		t.Errorf("current was mutated: %v", current)
	}
	if !reflect.DeepEqual(add, CgroupSetFromSlice([]uint64{3})) {
		t.Errorf("add was mutated: %v", add)
	}
	if !reflect.DeepEqual(remove, CgroupSetFromSlice([]uint64{1})) {
		t.Errorf("remove was mutated: %v", remove)
	}
}

// fakeWhitelist records the operations applied to it and can be configured to
// fail for specific cgroup IDs.
type fakeWhitelist struct {
	updated  []uint64
	deleted  []uint64
	failOn   map[uint64]bool
	failKind string // "update" or "delete"
}

func (f *fakeWhitelist) Update(id uint64) error {
	f.updated = append(f.updated, id)
	if f.failKind == "update" && f.failOn[id] {
		return errors.New("update failed")
	}
	return nil
}

func (f *fakeWhitelist) Delete(id uint64) error {
	f.deleted = append(f.deleted, id)
	if f.failKind == "delete" && f.failOn[id] {
		return errors.New("delete failed")
	}
	return nil
}

func TestApplyCgroupWhitelist_AppliesMinimalDiff(t *testing.T) {
	w := &fakeWhitelist{}
	current := CgroupSetFromSlice([]uint64{1, 2})
	add := CgroupSetFromSlice([]uint64{3})
	remove := CgroupSetFromSlice([]uint64{1})

	diff, err := ApplyCgroupWhitelist(w, current, add, remove)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []uint64{3}; !reflect.DeepEqual(w.updated, want) {
		t.Errorf("updated = %v, want %v", w.updated, want)
	}
	if want := []uint64{1}; !reflect.DeepEqual(w.deleted, want) {
		t.Errorf("deleted = %v, want %v", w.deleted, want)
	}
	if want := CgroupSetFromSlice([]uint64{2, 3}); !reflect.DeepEqual(diff.Desired, want) {
		t.Errorf("Desired = %v, want %v", diff.Desired, want)
	}
}

func TestApplyCgroupWhitelist_ContinuesPastFailure(t *testing.T) {
	w := &fakeWhitelist{failOn: map[uint64]bool{4: true}, failKind: "update"}
	current := CgroupSetFromSlice([]uint64{})
	add := CgroupSetFromSlice([]uint64{4, 5})

	_, err := ApplyCgroupWhitelist(w, current, add, nil)
	if err == nil {
		t.Fatal("expected an error from the failing update")
	}
	// Both updates should have been attempted despite the failure on 4.
	if want := []uint64{4, 5}; !reflect.DeepEqual(w.updated, want) {
		t.Errorf("updated = %v, want %v (should attempt all)", w.updated, want)
	}
}
