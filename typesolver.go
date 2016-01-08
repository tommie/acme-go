package acme

import (
	"fmt"

	"github.com/tommie/acme-go/protocol"
)

// A TypeSolver is a Solver split by challenge type. Each solver is
// assigned challenges by type. If the same solver object is used for
// multiple types, the challenges may be merged into a single call to
// Solve.
type TypeSolver map[protocol.ChallengeType]Solver

func (s TypeSolver) Cost(cs []protocol.Challenge) (float64, error) {
	sacs, err := s.assignSolvers(cs)
	if err != nil {
		return 0, err
	}

	var ret float64
	for _, sac := range sacs {
		cost, err := sac.s.Cost(sac.cs)
		if err != nil {
			return 0, err
		}
		ret += cost
	}

	return ret, nil
}

func (s TypeSolver) Solve(cs []protocol.Challenge) ([]protocol.Response, func() error, error) {
	sacs, err := s.assignSolvers(cs)
	if err != nil {
		return nil, nil, err
	}

	var stopFuncs []func() error
	stopAll := func() error {
		var err error
		for _, f := range stopFuncs {
			ferr := f()
			if ferr != nil {
				err = ferr
			}
		}
		return err
	}
	errStop := stopAll
	defer errStop()

	allResps := make([]protocol.Response, len(cs))
	for _, sac := range sacs {
		resps, stop, err := sac.s.Solve(sac.cs)
		if err != nil {
			return nil, nil, err
		}
		stopFuncs = append(stopFuncs, stop)
		if len(resps) != len(sac.cs) {
			return nil, nil, fmt.Errorf("solver %v was given %d challenges, but returned %d responses", sac.s, len(sac.cs), len(resps))
		}
		// Revert to original order.
		for i := range sac.cs {
			allResps[sac.cis[i]] = resps[i]
		}
	}

	errStop = func() error { return nil }
	return allResps, stopAll, nil
}

// assignSolvers assigns the given challenges to solvers. Returns
// ErrUnsolvable if any challenge has no solver. This should be
// deterministic in the set of solvers and slice of challenges
// provided.
func (s TypeSolver) assignSolvers(cs []protocol.Challenge) ([]solverChallenges, error) {
	cmap := map[Solver]solverChallenges{}
	for ci, ch := range cs {
		s, ok := s[ch.GetType()]
		if !ok {
			// No solver for this challenge type.
			return nil, ErrUnsolvable
		}
		sac := cmap[s]
		sac.s = s
		sac.cs = append(sac.cs, ch)
		sac.cis = append(sac.cis, ci)
		cmap[s] = sac
	}

	var ret []solverChallenges
	for _, sacs := range cmap {
		ret = append(ret, sacs)
	}

	return ret, nil
}

type solverChallenges struct {
	s   Solver
	cs  []protocol.Challenge
	cis []int
}
