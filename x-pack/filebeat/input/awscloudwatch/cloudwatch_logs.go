package awscloudwatch

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/pkg/errors"
)

type cloudwatchLogsProcessorFactory struct {
	ctx       context.Context
	svc       *cloudwatchlogs.Client
	publisher beat.Client
}

func newCloudwatchLogsProcessorFactory(
	ctx context.Context,
	svc *cloudwatchlogs.Client,
	publisher beat.Client,
) *cloudwatchLogsProcessorFactory {
	return &cloudwatchLogsProcessorFactory{
		ctx:       ctx,
		svc:       svc,
		publisher: publisher,
	}
}

func (factory *cloudwatchLogsProcessorFactory) Create(
	acker *eventACKTracker,
	logger *logp.Logger,
	regionName string,
	logGroupName string,
	logStreams []string,
	logStreamPrefix string,
	startTime int64,
	endTime int64,
) cloudwatchLogsHandler {
	return &cloudwatchLogsProcessor{
		regionName:      regionName,
		logGroupName:    logGroupName,
		logStreams:      logStreams,
		logStreamPrefix: logStreamPrefix,
		startTime:       startTime,
		endTime:         endTime,

		logger:    logger,
		ctx:       factory.ctx,
		acker:     acker,
		svc:       factory.svc,
		publisher: factory.publisher,
	}
}

type cloudwatchLogsProcessor struct {
	regionName      string
	logGroupName    string
	logStreams      []string
	logStreamPrefix string
	startTime       int64
	endTime         int64

	logger    *logp.Logger
	ctx       context.Context
	acker     *eventACKTracker
	svc       *cloudwatchlogs.Client
	publisher beat.Client
}

func (p *cloudwatchLogsProcessor) ProcessLogs() error {
	// construct FilterLogEventsInput
	filterLogEventsInput := p.constructFilterLogEventsInput()

	// make API request
	req := p.svc.FilterLogEventsRequest(filterLogEventsInput)
	paginator := cloudwatchlogs.NewFilterLogEventsPaginator(req)
	for paginator.Next(p.ctx) {
		page := paginator.CurrentPage()

		logEvents := page.Events
		p.logger.Debugf("Processing #%v events", len(logEvents))
		p.processLogEvents(logEvents, p.acker)
	}

	if err := paginator.Err(); err != nil {
		return errors.Wrap(err, "error FilterLogEvents with Paginator")
	}

	return nil
}
func (p *cloudwatchLogsProcessor) Wait() {
	p.acker.Wait()
}

func (p *cloudwatchLogsProcessor) constructFilterLogEventsInput() *cloudwatchlogs.FilterLogEventsInput {
	filterLogEventsInput := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: awssdk.String(p.logGroupName),
		StartTime:    awssdk.Int64(p.startTime),
		EndTime:      awssdk.Int64(p.endTime),
	}

	if len(p.logStreams) > 0 {
		filterLogEventsInput.LogStreamNames = p.logStreams
	}

	if p.logStreamPrefix != "" {
		filterLogEventsInput.LogStreamNamePrefix = awssdk.String(p.logStreamPrefix)
	}
	return filterLogEventsInput
}

func (p *cloudwatchLogsProcessor) processLogEvents(logEvents []cloudwatchlogs.FilteredLogEvent, acker *eventACKTracker) {
	beatEvents := make([]beat.Event, 0, len(logEvents))
	for _, logEvent := range logEvents {
		acker.Add()
		event := createEvent(logEvent, p.logGroupName, p.regionName)
		event.Private = acker
		beatEvents = append(beatEvents, event)
	}
	p.publisher.PublishAll(beatEvents)
}

func createEvent(logEvent cloudwatchlogs.FilteredLogEvent, logGroup string, regionName string) beat.Event {
	event := beat.Event{
		Timestamp: time.Unix(*logEvent.Timestamp/1000, 0).UTC(),
		Fields: common.MapStr{
			"message":       *logEvent.Message,
			"log.file.path": logGroup + "/" + *logEvent.LogStreamName,
			"event": common.MapStr{
				"id":       *logEvent.EventId,
				"ingested": time.Now(),
			},
			"awscloudwatch": common.MapStr{
				"log_group":      logGroup,
				"log_stream":     *logEvent.LogStreamName,
				"ingestion_time": time.Unix(*logEvent.IngestionTime/1000, 0),
			},
			"cloud": common.MapStr{
				"provider": "aws",
				"region":   regionName,
			},
		},
	}
	event.SetID(*logEvent.EventId)

	return event
}
