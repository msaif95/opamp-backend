package connection

import "testing"

func TestShedCount(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mine   int
		others []int
		want   int
	}{
		{"single replica never sheds", 20000, nil, 0},
		{"balanced", 6700, []int{6600, 6700}, 0},
		{"within tolerance", 7000, []int{6500, 6500}, 0},
		{"too few to bother", 25, []int{0, 0}, 0},
		// Fair share is 6667; excess 3333; half would be 1666 but the per-round cap is 5% of 10000.
		{"one replica just restarted", 10000, []int{10000, 0}, 500},
		{"the empty replica itself", 0, []int{10000, 10000}, 0},
		// Fair share 500; excess 500; half is 250 but capped at 5% of 1000.
		{"small fleet", 1000, []int{0}, 50},
		// Fair 100; excess 60; half is 30, cap would be 8, so 8.
		{"cap applies to small counts", 160, []int{40}, 8},
	} {
		if got := shedCount(tc.mine, tc.others); got != tc.want {
			t.Errorf("%s: shedCount(%d, %v) = %d, want %d", tc.name, tc.mine, tc.others, got, tc.want)
		}
	}
}

// Repeated rounds must converge and never empty a replica below its share.
func TestShedCountConverges(t *testing.T) {
	loads := []int{10000, 10000, 0}
	for round := 0; round < 200; round++ {
		next := append([]int(nil), loads...)
		for i, mine := range loads {
			others := append(append([]int(nil), loads[:i]...), loads[i+1:]...)
			n := shedCount(mine, others)
			next[i] -= n
			// The load balancer spreads the dropped agents evenly over all replicas.
			for j := range next {
				next[j] += n / len(loads)
			}
			next[i] += n % len(loads)
		}
		loads = next
	}
	for _, n := range loads {
		if n < 5300 || n > 7400 {
			t.Fatalf("did not converge near the fair share of 6667: %v", loads)
		}
	}
}
