// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package awscloudwatch

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/pkg/errors"

	"github.com/elastic/beats/v7/filebeat/beater"
	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/beats/v7/libbeat/feature"
	"github.com/elastic/beats/v7/libbeat/logp"
	awscommon "github.com/elastic/beats/v7/x-pack/libbeat/common/aws"
	"github.com/elastic/go-concert/unison"
)

const (
	inputName    = "aws-cloudwatch"
	oldInputName = "awscloudwatch"
)

func Plugin(store beater.StateStore) v2.Plugin {
	return v2.Plugin{
		Name:       inputName,
		Stability:  feature.Stable,
		Deprecated: false,
		Info:       "Collect logs from s3",
		Manager:    &cloudwatchInputManager{name: inputName, store: store},
	}
}

func PluginWithOldName(store beater.StateStore) v2.Plugin {
	return v2.Plugin{
		Name:       oldInputName,
		Stability:  feature.Stable,
		Deprecated: false,
		Info:       "Collect logs from s3",
		Manager:    &cloudwatchInputManager{name: oldInputName, store: store},
	}
}

type cloudwatchInputManager struct {
	name  string
	store beater.StateStore
}

func (im *cloudwatchInputManager) Init(grp unison.Group, mode v2.Mode) error {
	return nil
}

func (im *cloudwatchInputManager) Create(cfg *common.Config) (v2.Input, error) {
	return newInput(im.name, cfg, im.store)
}

// awsCloudWatchInput is a input for AWS CloudWatch logs
type awsCloudWatchInput struct {
	name      string
	config    config
	awsConfig awssdk.Config
	store     beater.StateStore
	logger    *logp.Logger
}

// newInput creates a new aws-cloudwatch input
func newInput(name string, cfg *common.Config, store beater.StateStore) (v2.Input, error) {
	cfgwarn.Beta("aws-cloudwatch input type is used")
	logger := logp.NewLogger(inputName)

	// Extract and validate the input's configuration.
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return nil, errors.Wrap(err, "failed unpacking config")
	}
	logger.Debug("aws-cloudwatch input config = ", config)

	if config.Type == oldInputName {
		logger.Warnf("%s input name is deprecated, please use %s instead", oldInputName, inputName)
	}

	if config.LogGroupARN != "" {
		logGroupName, regionName, err := parseARN(config.LogGroupARN)
		if err != nil {
			return nil, errors.Wrap(err, "parse log group ARN failed")
		}

		config.LogGroupName = logGroupName
		config.RegionName = regionName
	}

	awsConfig, err := awscommon.InitializeAWSConfig(config.AwsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "InitializeAWSConfig failed")
	}
	awsConfig.Region = config.RegionName

	in := &awsCloudWatchInput{
		name:      name,
		config:    config,
		awsConfig: awsConfig,
		store:     store,
		logger:    logger,
	}

	return in, nil
}

// Nmae returns the name of the input.
func (in *awsCloudWatchInput) Name() string {
	return in.name
}

func (in *awsCloudWatchInput) Test(ctx v2.TestContext) error {
	return nil
}

// Run runs the input
func (in *awsCloudWatchInput) Run(inputContext v2.Context, pipeline beat.Pipeline) error {
	// Please see https://docs.aws.amazon.com/general/latest/gr/cwl_region.html for more info on Amazon CloudWatch Logs endpoints.
	cwConfig := awscommon.EnrichAWSConfigWithEndpoint(in.config.AwsConfig.Endpoint, "logs", in.config.RegionName, in.awsConfig)
	svc := cloudwatchlogs.New(cwConfig)

	// Wrap input Context's cancellation Done channel a context.Context. This
	// goroutine stops with the parent closes the Done channel.
	ctx, cancelInputCtx := context.WithCancel(context.Background())
	go func() {
		defer cancelInputCtx()
		select {
		case <-inputContext.Cancelation.Done():
		case <-ctx.Done():
		}
	}()
	defer cancelInputCtx()

	// Create client for publishing events and receive notification of their ACKs.
	publisher, err := pipeline.ConnectWith(beat.ClientConfig{
		CloseRef:   inputContext.Cancelation,
		ACKHandler: newEventACKHandler(),
	})
	if err != nil {
		return fmt.Errorf("failed to create pipeline client: %w", err)
	}
	defer publisher.Close()

	// Normalize the log group names.
	var logGroupNames []string
	if in.config.LogGroupName != "" {
		logGroupNames = append(logGroupNames, in.config.LogGroupName)
	}
	if in.config.LogGroupNamePrefix != "" {
		if matched, err := getLogGroupNames(in.config.LogGroupNamePrefix, in.logger, svc); err != nil {
			return fmt.Errorf("failed to get log group names: %w", err)
		} else {
			logGroupNames = append(logGroupNames, matched...)
		}
	}
	if len(logGroupNames) == 0 {
		return errors.New("no log group names found")
	}

	// Create a poller
	poller, err := newCloudwatchLogsPoller(
		in.config,
		logGroupNames,
		in.logger,
		newCloudwatchLogsProcessorFactory(ctx, svc, publisher),
	)
	if err != nil {
		return fmt.Errorf("failed to create poller: %w", err)
	}
	poller.Poll(ctx)
	return nil
}

func parseARN(logGroupARN string) (string, string, error) {
	arnParsed, err := arn.Parse(logGroupARN)
	if err != nil {
		return "", "", errors.Errorf("error Parse arn %s: %v", logGroupARN, err)
	}

	if strings.Contains(arnParsed.Resource, ":") {
		resourceARNSplit := strings.Split(arnParsed.Resource, ":")
		if len(resourceARNSplit) >= 2 && resourceARNSplit[0] == "log-group" {
			return resourceARNSplit[1], arnParsed.Region, nil
		}
	}
	return "", "", errors.Errorf("cannot get log group name from log group ARN: %s", logGroupARN)
}

func getLogGroupNames(logGroupNamePrefix string, logger *logp.Logger, svc *cloudwatchlogs.Client) ([]string, error) {
	// construct DescribeLogGroupsInput
	filterLogEventsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupNamePrefix),
	}

	// make API request
	req := svc.DescribeLogGroupsRequest(filterLogEventsInput)
	p := cloudwatchlogs.NewDescribeLogGroupsPaginator(req)
	var logGroupNames []string
	for p.Next(context.TODO()) {
		page := p.CurrentPage()
		logger.Debugf("Collecting #%v log group names", len(page.LogGroups))
		for _, lg := range page.LogGroups {
			logGroupNames = append(logGroupNames, *lg.LogGroupName)
		}
	}

	if err := p.Err(); err != nil {
		logger.Error("failed DescribeLogGroupsRequest: ", err)
		return logGroupNames, err
	}
	return logGroupNames, nil
}
