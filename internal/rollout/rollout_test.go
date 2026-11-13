package rollout

import (
	"errors"
	"reflect"
	"testing"
)

func TestStepBounds(t *testing.T) {
	for _, tc := range []struct {
		steps []int
		total int
		want  []int32
	}{
		{[]int{1, 10, 50, 100}, 20000, []int32{200, 2000, 10000, 20000}},
		{[]int{1, 10, 50, 100}, 66, []int32{1, 7, 33, 66}},
		// Tiny targets: steps that add no agents collapse instead of leaving an empty batch.
		{[]int{1, 10, 50, 100}, 2, []int32{1, 2}},
		{[]int{1, 2, 100}, 10, []int32{1, 10}},
		{[]int{100}, 5, []int32{5}},
	} {
		if got := stepBounds(tc.steps, tc.total); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("stepBounds(%v, %d) = %v, want %v", tc.steps, tc.total, got, tc.want)
		}
	}
}

func TestParamsValidate(t *testing.T) {
	base := Params{BatchSize: 100, MaxFailurePct: 2}
	for name, tc := range map[string]struct {
		mutate func(*Params)
		ok     bool
	}{
		"fixed batches":          {func(*Params) {}, true},
		"canary":                 {func(p *Params) { p.CanarySteps = []int{1, 10, 50, 100} }, true},
		"single step":            {func(p *Params) { p.CanarySteps = []int{100} }, true},
		"not ending at 100":      {func(p *Params) { p.CanarySteps = []int{1, 10} }, false},
		"not increasing":         {func(p *Params) { p.CanarySteps = []int{10, 10, 100} }, false},
		"zero step":              {func(p *Params) { p.CanarySteps = []int{0, 100} }, false},
		"empty steps":            {func(p *Params) { p.CanarySteps = []int{} }, false},
		"batch too small":        {func(p *Params) { p.BatchSize = 0 }, false},
		"threshold out of range": {func(p *Params) { p.MaxFailurePct = 101 }, false},
	} {
		p := base
		tc.mutate(&p)
		err := p.validate()
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrInvalid)) {
			t.Errorf("%s: err = %v, want ok = %v", name, err, tc.ok)
		}
	}
}
