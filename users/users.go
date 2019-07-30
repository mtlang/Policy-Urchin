package users

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/araddon/dateparse"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/spf13/viper"

	logger "github.com/mtlang/Policy-Urchin/log"
	myTrail "github.com/mtlang/Policy-Urchin/cloudtrail"
)

type output struct {
	UserFindings []userFindings `json:"Users"`
}

type userFindings struct {
	Username string    `json:"Username"`
	Findings []finding `json:"Findings"`
}

type finding struct {
	SourceDNS       []string `json:"sourceDNS"`
	SourceIPAddress string   `json:"sourceIPAddress"`
	UserAgent       string   `json:"userAgent"`
	AwsRegion       string   `json:"awsRegion"`
	AwsService      string   `json:"awsService"`
	LastEvent       string   `json:"lastEvent"`
	InstanceID      string   `json:"instanceID"`
	InstanceName    string   `json:"instanceName"`
}

type ipRanges struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix string `json:"ip_prefix"`
		Region   string `json:"region"`
		Service  string `json:"service"`
	}
}

// AmazonIps is a struct representing known IP ranges of Amazon services
var AmazonIps ipRanges

// Users ...
func Users(log logger.Logger, sess client.ConfigProvider) {
	userNames := []string{}
	findingsByUser := make(map[string][]finding)
	iamClient := iam.New(sess)
	userName := viper.GetString("user")

	AmazonIps = getAmazonIPs(log)

	if userName == "" {
		// If user not specified, analyze all users
		listUsersOutput, err := iamClient.ListUsers(&iam.ListUsersInput{})
		if err != nil {
			log.Fatal(err)
		}
		for _, user := range listUsersOutput.Users {
			userNames = append(userNames, *user.UserName)
		}
		for *listUsersOutput.IsTruncated {
			listUsersOutput, err := iamClient.ListUsers(&iam.ListUsersInput{
				Marker: listUsersOutput.Marker,
			})
			if err != nil {
				log.Fatal(err)
			}
			for _, user := range listUsersOutput.Users {
				userNames = append(userNames, *user.UserName)
			}
		}
		log.Info("Analyzing all users")
	} else {
		// Validate user
		getUserInput := iam.GetUserInput{
			UserName: aws.String(userName),
		}
		_, err := iamClient.GetUser(&getUserInput)
		if err != nil {
			if strings.Contains(err.Error(), "NoSuchEntity") {
				log.Infof("User: \"%s\" not found...", userName)
				return
			}
			log.Fatal(err)
		}
		userNames = []string{userName}
		log.Infof("Analyzing %s", userName)
	}

	for _, user := range userNames {
		findingsByUser[user] = getFindingsForUser(log, sess, user)
	}

	outputResults(log, findingsByUser)
}

func getAmazonIPs(log logger.Logger) ipRanges {
	retval := ipRanges{}

	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(body, &retval)

	return retval
}

func getFindingsForUser(log logger.Logger, sess client.ConfigProvider, user string) []finding {
	retval := []finding{}
	allRegions := []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1",
		"eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "ap-northeast-1", "ap-northeast-2",
		"ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ap-south-1", "sa-east-1"}
	minEvents := viper.GetInt("events")

	regions := []string{viper.GetString("region")}
	if strings.ToLower(viper.GetString("region")) == "all" {
		regions = allRegions
	}

	for _, region := range regions {
		cloudTrailClient := cloudtrail.New(sess, aws.NewConfig().WithRegion(region))
		existenceMap := make(map[string]bool)

		eventCount := 0
		lookupEventsInput := cloudtrail.LookupEventsInput{
			LookupAttributes: []*cloudtrail.LookupAttribute{
				&cloudtrail.LookupAttribute{
					AttributeKey:   aws.String("Username"),
					AttributeValue: aws.String(user),
				},
			},
		}

		if viper.GetString("start-time") != "" {
			startTime, err := dateparse.ParseAny(viper.GetString("start-time"))
			if err != nil {
				log.Fatal(err)
			}
			lookupEventsInput.StartTime = &startTime
		}
		if viper.GetString("end-time") != "" {
			endTime, err := dateparse.ParseAny(viper.GetString("end-time"))
			if err != nil {
				log.Fatal(err)
			}
			lookupEventsInput.EndTime = &endTime
		}

		lookupEventsOutput, err := cloudTrailClient.LookupEvents(&lookupEventsInput)
		if err != nil {
			log.Fatal(err)
		}
		for _, event := range lookupEventsOutput.Events {
			eventCount++
			fullEvent := myTrail.FullEvent{}
			json.Unmarshal([]byte(*event.CloudTrailEvent), &fullEvent)
			newFinding := finding{
				UserAgent:       fullEvent.UserAgent,
				SourceIPAddress: fullEvent.SourceIPAddress,
				LastEvent:       event.EventTime.String(),
			}

			if !existenceMap[newFinding.SourceIPAddress+newFinding.AwsRegion] {

				existenceMap[newFinding.SourceIPAddress+newFinding.AwsRegion] = true

				newFinding = addAwsInfoToFinding(log, newFinding)
				names, err := net.LookupAddr(newFinding.SourceIPAddress)
				if err == nil {
					newFinding.SourceDNS = names
				}

				retval = append(retval, newFinding)
			}
		}
		for eventCount < minEvents {
			// Other pages
			if lookupEventsOutput.NextToken == nil {
				break
			}
			if *lookupEventsOutput.NextToken == "" {
				break
			}
			log.Infof("%d events found. Continuing...", eventCount)
			lookupEventsInput.NextToken = lookupEventsOutput.NextToken

			lookupEventsOutput, err = cloudTrailClient.LookupEvents(&lookupEventsInput)
			if err != nil {
				log.Fatal(err)
			}
			for _, event := range lookupEventsOutput.Events {
				eventCount++
				fullEvent := myTrail.FullEvent{}
				json.Unmarshal([]byte(*event.CloudTrailEvent), &fullEvent)
				newFinding := finding{
					UserAgent:       fullEvent.UserAgent,
					SourceIPAddress: fullEvent.SourceIPAddress,
					LastEvent:       event.EventTime.String(),
				}

				if !existenceMap[newFinding.SourceIPAddress+newFinding.AwsRegion] {

					existenceMap[newFinding.SourceIPAddress+newFinding.AwsRegion] = true

					newFinding = addAwsInfoToFinding(log, newFinding)
					names, err := net.LookupAddr(newFinding.SourceIPAddress)
					if err == nil {
						newFinding.SourceDNS = names
					}

					retval = append(retval, newFinding)
				}
			}
		}
	}

	return retval
}

// func findingsAreEqual(a finding, b finding) bool {
// 	if (a.UserAgent == b.UserAgent) && (a.SourceIPAddress == b.SourceIPAddress) {
// 		return true
// 	}
// 	return false
// }

func addAwsInfoToFinding(log logger.Logger, input finding) finding {
	var retval finding
	retval = finding(input)

	findingIP := net.ParseIP(retval.SourceIPAddress)

	found := false
	for _, prefix := range AmazonIps.Prefixes {
		_, cidrToCheck, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			log.Fatal(err)
		}

		if cidrToCheck.Contains(findingIP) {
			found = true
			retval.AwsRegion = prefix.Region
			retval.AwsService = prefix.Service

			if retval.AwsService != "AMAZON" {
				break
			}
		}
	}

	if !found {
		retval.AwsRegion = "Not Found"
		retval.AwsService = "Not Found"
	}

	if retval.AwsService == "EC2" {
		sess := session.Must(session.NewSession())
		ec2Client := ec2.New(sess, aws.NewConfig().WithRegion(retval.AwsRegion))
		describeInstancesInput := ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("ip-address"),
					Values: []*string{aws.String(retval.SourceIPAddress)},
				},
			},
		}

		describeInstancesOutput, err := ec2Client.DescribeInstances(&describeInstancesInput)
		if err != nil {
			log.Fatal(err)
		}
		if len(describeInstancesOutput.Reservations) == 0 {
			retval.InstanceID = "Not Found"
			retval.InstanceName = "Not Found"
		} else {
			retval.InstanceID = *describeInstancesOutput.Reservations[0].Instances[0].InstanceId
			retval.InstanceName = "<No Name>"
			for _, tag := range describeInstancesOutput.Reservations[0].Instances[0].Tags {
				if *tag.Key == "Name" {
					retval.InstanceName = *tag.Value
					break
				}
			}
		}

	}

	return retval
}

func outputResults(log logger.Logger, findingsByUser map[string][]finding) {
	outStruct := output{}

	for user, findings := range findingsByUser {
		toAdd := userFindings{
			Username: user,
			Findings: findings,
		}
		outStruct.UserFindings = append(outStruct.UserFindings, toAdd)
	}

	outBytes, err := json.Marshal(outStruct)
	if err != nil {
		log.Fatal(err)
	}

	outputFile := viper.GetString("output")
	if outputFile == "" {
		fmt.Println(string(outBytes))
	} else {
		file, err := os.Create(outputFile)
		if err != nil {
			panic(err)
		}

		_, err = file.Write(outBytes)
		if err != nil {
			panic(err)
		}
		log.Infof("Wrote results to %s", outputFile)
	}
}
