package server

import (
	"time"

	"google.golang.org/grpc"
)

// GracefulStop drains the inner server, then the outer server, within budget.
// Both must be non-nil.
//
// ORDER MATTERS, and getting it wrong hangs shutdown outright.
//
// Every Open handler blocks until its inner connection closes, and the inner
// connection closes only when the INNER server is done with it. So stopping the
// outer server first waits on tunnel handlers that are waiting on the inner
// server that is never asked to stop: a deadlock, resolved only by a timeout
// that hard-stops every direct-path client mid-call too.
//
// Stopping the inner server first closes its listener, sends GOAWAY on every
// tunnelled connection, drains their calls and then closes them, which releases
// every Open handler. Only direct-path calls are left for the outer server to
// drain. The budget is split across the two phases rather than given to each:
// the inner server gets half, the outer server gets what remains up to budget,
// so the total stays within budget. A server that is not drained in its share is
// stopped hard.
func (s *Service) GracefulStop(inner, outer *grpc.Server, budget time.Duration) {
	start := time.Now()
	innerDeadline := start.Add(budget / 2)
	s.stopGracefully(inner, "inner (tunnelled) gRPC server", time.Until(innerDeadline))
	s.stopGracefully(outer, "outer gRPC server", time.Until(start.Add(budget)))
}

// stopGracefully drains gs, falling back to a hard stop after budget.
func (s *Service) stopGracefully(gs *grpc.Server, name string, budget time.Duration) {
	if budget <= 0 {
		s.cfg.log.Warn("supertls: no shutdown budget left, forcing stop", "server", name)
		gs.Stop()
		return
	}

	stopped := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-stopped:
		s.cfg.log.Info("supertls: stopped gracefully", "server", name)
	case <-timer.C:
		s.cfg.log.Warn("supertls: graceful shutdown timed out, forcing stop", "server", name, "budget", budget)
		gs.Stop()
		<-stopped
	}
}
