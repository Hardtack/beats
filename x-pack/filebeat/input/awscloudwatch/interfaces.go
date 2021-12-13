package awscloudwatch

import "github.com/elastic/beats/v7/libbeat/logp"

type cloudwatchLogsHandlerFactory interface {
	Create(
		acker *eventACKTracker,
		logger *logp.Logger,
		regionName string,
		logGroupName string,
		logStreams []string,
		logStreamPrefix string,
		startTime int64,
		endTime int64,
	) cloudwatchLogsHandler
}

type cloudwatchLogsHandler interface {
	// ProcessLogs fetch log events from CloudWatch Logs log group and publish them.
	// It returns when processing finishes or when it encounters
	// an unrecoverable error. It does not wait for the events to be ACKed by
	// the publisher before returning (use eventACKTracker's Wait() method to
	// determine this).
	ProcessLogs() error

	// Wait waits for every event published by ProcessLogs() to be ACKed
	// by the publisher before returning. Internally it uses the
	// cloudwatchLogsHandler eventACKTracker's Wait() method
	Wait()
}
