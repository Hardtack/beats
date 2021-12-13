package awscloudwatch

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/beats/v7/libbeat/logp"
)

type cloudwatchLogsPoller struct {
	logGroupNames   []string
	regionName      string
	logStreams      []string
	logStreamPrefix string
	startPosition   string

	APITimeout    time.Duration
	APISleep      time.Duration
	scanFrequency time.Duration
	latency       time.Duration

	cloudwatchLogsHandlerFactory cloudwatchLogsHandlerFactory

	logger *logp.Logger
}

func newCloudwatchLogsPoller(
	config config,
	logGroupNames []string,
	logger *logp.Logger,
	cloudwatchLogsHandlerFactory cloudwatchLogsHandlerFactory,
) (*cloudwatchLogsPoller, error) {
	poller := &cloudwatchLogsPoller{
		regionName:                   config.RegionName,
		logGroupNames:                logGroupNames,
		logStreams:                   config.LogStreams,
		logStreamPrefix:              config.LogStreamPrefix,
		startPosition:                config.StartPosition,
		APITimeout:                   config.APITimeout,
		APISleep:                     config.APISleep,
		scanFrequency:                config.ScanFrequency,
		latency:                      config.Latency,
		cloudwatchLogsHandlerFactory: cloudwatchLogsHandlerFactory,
		logger:                       logger,
	}
	logger.Infof("Found %v log groups, %s", len(poller.logGroupNames), strings.Join(poller.logGroupNames, ", "))

	return poller, nil
}

func (poller *cloudwatchLogsPoller) Poll(ctx context.Context) error {
	workerWg := new(sync.WaitGroup)

	type pollState struct {
		logGroupName string
		nextPoll     time.Time
		prevEndTime  int64
		polling      bool
	}

	pollStatesMap := make(map[string]pollState)
	var pollStateLock sync.Mutex

	now := time.Now()
	for _, logGroupName := range poller.logGroupNames {
		pollStatesMap[logGroupName] = pollState{
			logGroupName,
			now,
			0,
			false,
		}
	}
	for ctx.Err() == nil {
		var readyStates []pollState
		var waitingStates []pollState
		// Find log groups that are ready to be polled
		now = time.Now()
		func() {
			pollStateLock.Lock()
			defer pollStateLock.Unlock()

			for _, pollState := range pollStatesMap {
				if pollState.polling {
					continue
				}
				if pollState.nextPoll.Before(now) || pollState.nextPoll.Equal(now) {
					readyStates = append(readyStates, pollState)
				} else {
					waitingStates = append(waitingStates, pollState)
				}
			}
		}()

		// Run ready states now
		for _, readyState := range readyStates {
			workerWg.Add(1)
			go func(readyState pollState) {
				defer workerWg.Done()

				startTime, endTime := getStartPosition(
					poller.startPosition,
					now,
					readyState.prevEndTime,
					poller.scanFrequency,
					poller.latency,
				)
				handler := poller.cloudwatchLogsHandlerFactory.Create(
					newEventACKTracker(ctx),
					poller.logger,
					readyState.logGroupName,
					poller.regionName,
					poller.logStreams,
					poller.logStreamPrefix,
					startTime,
					endTime,
				)
				if err := handler.ProcessLogs(); err != nil {
					err = errors.Wrap(err, "ProcessLogs failed")
					poller.logger.Error(err)
				}
				handler.Wait()

				// Update the poll state
				pollStateLock.Lock()
				defer pollStateLock.Unlock()
				readyState.polling = false
				readyState.nextPoll = time.Now().Add(poller.scanFrequency)
				readyState.prevEndTime = endTime
				pollStatesMap[readyState.logGroupName] = readyState
			}(readyState)
		}

		// Get the next poll time for waiting states
		sleepDuration := poller.scanFrequency
		for _, waitingState := range waitingStates {
			if waitingState.nextPoll.Before(now.Add(sleepDuration)) {
				sleepDuration = waitingState.nextPoll.Sub(now)
			}
		}
		// Sleep for the next poll time
		select {
		case <-ctx.Done():
		case <-time.After(sleepDuration):
		}
	}

	workerWg.Wait()

	if errors.Is(ctx.Err(), context.Canceled) {
		// A canceled context is a normal shutdown.
		return nil
	}
	return ctx.Err()
}

func getStartPosition(startPosition string, currentTime time.Time, prevEndTime int64, scanFrequency time.Duration, latency time.Duration) (startTime int64, endTime int64) {
	if latency != 0 {
		// add latency if config is not 0
		currentTime = currentTime.Add(latency * -1)
	}

	switch startPosition {
	case "beginning":
		if prevEndTime != int64(0) {
			return prevEndTime, currentTime.UnixNano() / int64(time.Millisecond)
		}
		return 0, currentTime.UnixNano() / int64(time.Millisecond)
	case "end":
		if prevEndTime != int64(0) {
			return prevEndTime, currentTime.UnixNano() / int64(time.Millisecond)
		}
		return currentTime.Add(-scanFrequency).UnixNano() / int64(time.Millisecond), currentTime.UnixNano() / int64(time.Millisecond)
	}
	return
}
