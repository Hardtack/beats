// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package awscloudwatch

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/cloudwatchlogsiface"
)

// MockCloudwatchlogsClient struct is used for unit tests.
type MockCloudwatchlogsClient struct {
	cloudwatchlogsiface.ClientAPI
}

var (
	mockSvc = &MockCloudwatchlogsClient{}
)

func (m *MockCloudwatchlogsClient) FilterLogEventsRequest(input *cloudwatchlogs.FilterLogEventsInput) cloudwatchlogs.FilterLogEventsRequest {
	events := []cloudwatchlogs.FilteredLogEvent{
		{
			EventId:       awssdk.String("id-1"),
			IngestionTime: awssdk.Int64(1590000000000),
			LogStreamName: awssdk.String("logStreamName1"),
			Message:       awssdk.String("test-message-1"),
			Timestamp:     awssdk.Int64(1590000000000),
		},
		{
			EventId:       awssdk.String("id-2"),
			IngestionTime: awssdk.Int64(1600000000000),
			LogStreamName: awssdk.String("logStreamName1"),
			Message:       awssdk.String("test-message-2"),
			Timestamp:     awssdk.Int64(1600000000000),
		},
	}

	httpReq, _ := http.NewRequest("", "", nil)
	return cloudwatchlogs.FilterLogEventsRequest{
		Request: &awssdk.Request{
			Data: &cloudwatchlogs.FilterLogEventsOutput{
				Events:    events,
				NextToken: awssdk.String(""),
			},
			HTTPRequest: httpReq,
		},
	}
}

func TestParseARN(t *testing.T) {
	logGroup, regionName, err := parseARN("arn:aws:logs:us-east-1:428152502467:log-group:test:*")
	assert.Equal(t, "test", logGroup)
	assert.Equal(t, "us-east-1", regionName)
	assert.NoError(t, err)
}
