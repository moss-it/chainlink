package offchainreporting

import (
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink/core/services/postgres"
	"gorm.io/gorm"

	"github.com/smartcontractkit/chainlink/core/gracefulpanic"

	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/pipeline"
	"github.com/smartcontractkit/chainlink/core/utils"
)

type RunResultSaver struct {
	utils.StartStopOnce

	db             *gorm.DB
	runResults     <-chan pipeline.RunWithResults
	pipelineRunner pipeline.Runner
	done           chan struct{}
	jobID          int32
}

func NewResultRunSaver(db *gorm.DB, runResults <-chan pipeline.RunWithResults, pipelineRunner pipeline.Runner, done chan struct{}, jobID int32) *RunResultSaver {
	return &RunResultSaver{
		db:             db,
		runResults:     runResults,
		pipelineRunner: pipelineRunner,
		done:           done,
		jobID:          jobID,
	}
}

func (r *RunResultSaver) Start() error {
	if !r.OkayToStart() {
		return errors.New("cannot start already started run result saver")
	}
	go gracefulpanic.WrapRecover(func() {
		for {
			select {
			case rr := <-r.runResults:
				logger.Debugw("RunSaver: saving job run", "run", rr.Run, "task results", rr.TaskRunResults)
				// We do not want save successful TaskRuns as OCR runs very frequently so a lot of records
				// are produced and the successful TaskRuns do not provide value.
				ctx, cancel := postgres.DefaultQueryCtx()
				defer cancel()
				_, err := r.pipelineRunner.InsertFinishedRun(r.db.WithContext(ctx), rr.Run, rr.TaskRunResults, false)
				if err != nil {
					logger.Errorw(fmt.Sprintf("error inserting finished results for job ID %v", r.jobID), "err", err)
				}
			case <-r.done:
				return
			}
		}
	})
	return nil
}

func (r *RunResultSaver) Close() error {
	if !r.OkayToStop() {
		return errors.New("cannot close unstarted run result saver")
	}
	r.done <- struct{}{}

	// In the unlikely event that there are remaining runResults to write,
	// drain the channel and save them.
	for {
		select {
		case rr := <-r.runResults:
			logger.Debugw("RunSaver: saving job run before exiting", "run", rr.Run, "task results", rr.TaskRunResults)
			ctx, cancel := postgres.DefaultQueryCtx()
			defer cancel()
			_, err := r.pipelineRunner.InsertFinishedRun(r.db.WithContext(ctx), rr.Run, rr.TaskRunResults, false)
			if err != nil {
				logger.Errorw(fmt.Sprintf("error inserting finished results for job ID %v", r.jobID), "err", err)
			}
		default:
			return nil
		}
	}
}
