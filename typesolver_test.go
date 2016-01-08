package acme

import (
	"reflect"
	"sort"
	"testing"

	"github.com/tommie/acme-go/protocol"
)

func TestTypeSolverCost(t *testing.T) {
	dns01Solver := &stubSolver{
		costs: map[protocol.ChallengeType]float64{protocol.ChallengeDNS01: 1},
	}
	http01Solver := &stubSolver{
		costs: map[protocol.ChallengeType]float64{protocol.ChallengeHTTP01: 2},
	}
	dns01Challenge := &protocol.DNS01Challenge{Type: protocol.ChallengeDNS01}
	http01Challenge := &protocol.HTTP01Challenge{Type: protocol.ChallengeHTTP01}
	tsts := []struct {
		name string
		sm   map[protocol.ChallengeType]Solver
		cs   []protocol.Challenge

		want float64
		err  error
	}{
		{
			name: "two",
			sm: map[protocol.ChallengeType]Solver{
				protocol.ChallengeDNS01:  dns01Solver,
				protocol.ChallengeHTTP01: http01Solver,
			},
			cs: []protocol.Challenge{
				dns01Challenge,
				http01Challenge,
			},

			want: 1 + 2,
		},
		{
			name: "no solver",
			cs: []protocol.Challenge{
				dns01Challenge,
			},

			err: ErrUnsolvable,
		},
	}

	for _, tst := range tsts {
		got, err := TypeSolver(tst.sm).Cost(tst.cs)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] Cost failed: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if got != tst.want {
			t.Errorf("[%s] Cost: got %v, want %v", tst.name, got, tst.want)
		}
	}
}

func TestTypeSolverSolve(t *testing.T) {
	dns01Resp := &protocol.DNS01Response{Type: protocol.ChallengeDNS01}
	http01Resp := &protocol.HTTP01Response{Type: protocol.ChallengeHTTP01}
	dns01Solver := &stubSolver{
		resps: map[protocol.ChallengeType]protocol.Response{protocol.ChallengeDNS01: dns01Resp},
	}
	http01Solver := &stubSolver{
		resps: map[protocol.ChallengeType]protocol.Response{protocol.ChallengeHTTP01: http01Resp},
	}
	combiSolver := &stubSolver{
		resps: map[protocol.ChallengeType]protocol.Response{
			protocol.ChallengeDNS01:  dns01Resp,
			protocol.ChallengeHTTP01: http01Resp,
		},
	}
	dns01Challenge := &protocol.DNS01Challenge{Type: protocol.ChallengeDNS01}
	http01Challenge := &protocol.HTTP01Challenge{Type: protocol.ChallengeHTTP01}
	tsts := []struct {
		name string
		sm   map[protocol.ChallengeType]Solver
		cs   []protocol.Challenge

		want []protocol.Response
		err  error
	}{
		{
			name: "two",
			sm: map[protocol.ChallengeType]Solver{
				protocol.ChallengeDNS01:  dns01Solver,
				protocol.ChallengeHTTP01: http01Solver,
			},
			cs: []protocol.Challenge{
				dns01Challenge,
				http01Challenge,
			},

			want: []protocol.Response{
				dns01Resp,
				http01Resp,
			},
		},
		{
			name: "combi",
			sm: map[protocol.ChallengeType]Solver{
				protocol.ChallengeDNS01:  combiSolver,
				protocol.ChallengeHTTP01: combiSolver,
			},
			cs: []protocol.Challenge{
				dns01Challenge,
				http01Challenge,
			},

			want: []protocol.Response{
				dns01Resp,
				http01Resp,
			},
		},
		{
			name: "no solver",
			cs: []protocol.Challenge{
				dns01Challenge,
			},

			err: ErrUnsolvable,
		},
	}

	for _, tst := range tsts {
		got, stop, err := TypeSolver(tst.sm).Solve(tst.cs)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] Solve failed: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if err == nil {
			if err := stop(); err != nil {
				t.Errorf("[%s] Solve stop failed: got %v, want prefix %v", tst.name, err, tst.err)
			}
		}
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("[%s] Solve: got %v, want %v", tst.name, got, tst.want)
		}
	}
}

func TestTypeSolverAssignSolvers(t *testing.T) {
	dns01Solver := &stubSolver{}
	http01Solver := &stubSolver{}
	dns01Challenge := &protocol.DNS01Challenge{Type: protocol.ChallengeDNS01}
	http01Challenge := &protocol.HTTP01Challenge{Type: protocol.ChallengeHTTP01}
	tsts := []struct {
		name string
		sm   map[protocol.ChallengeType]Solver
		cs   []protocol.Challenge

		want []solverChallenges
		err  error
	}{
		{
			name: "happy",
			sm: map[protocol.ChallengeType]Solver{
				protocol.ChallengeDNS01:  dns01Solver,
				protocol.ChallengeHTTP01: http01Solver,
			},
			cs: []protocol.Challenge{
				dns01Challenge,
				http01Challenge,
			},

			want: []solverChallenges{
				{dns01Solver, []protocol.Challenge{dns01Challenge}, []int{0}},
				{http01Solver, []protocol.Challenge{http01Challenge}, []int{1}},
			},
		},
		{
			name: "no solver",
			cs: []protocol.Challenge{
				dns01Challenge,
			},

			err: ErrUnsolvable,
		},
	}

	for _, tst := range tsts {
		got, err := TypeSolver(tst.sm).assignSolvers(tst.cs)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] assignSolvers failed: got %v, want prefix %v", tst.name, err, tst.err)
		}
		sort.Sort(bySolver(got))
		sort.Sort(bySolver(tst.want))
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("[%s] assignSolvers: got %v, want %v", tst.name, got, tst.want)
		}
	}
}

// bySolver creates a stable ordering, but only looks at pointer
// equivalence for s and cs[i]. Just enough for test stability.
type bySolver []solverChallenges

func (sacs bySolver) Len() int { return len(sacs) }
func (sacs bySolver) Less(i, j int) bool {
	si := reflect.ValueOf(sacs[i].s).Pointer()
	sj := reflect.ValueOf(sacs[j].s).Pointer()
	if si != sj {
		return si < sj
	}

	li := len(sacs[i].cs)
	lj := len(sacs[j].cs)
	if li != lj {
		return li < lj
	}

	for k := 0; k < li; k++ {
		ci := reflect.ValueOf(sacs[i].cs[k]).Pointer()
		cj := reflect.ValueOf(sacs[j].cs[k]).Pointer()
		if ci != cj {
			return ci < cj
		}
	}

	return false
}
func (sacs bySolver) Swap(i, j int) { sacs[i], sacs[j] = sacs[j], sacs[i] }
