package ec2

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ec2"

	logger "github.com/mtlang/Policy-Urchin/log"
	"github.com/mtlang/Policy-Urchin/cache"
)

// GetAllEc2Instances ...
func GetAllEc2Instances(log logger.Logger, sess client.ConfigProvider) map[string][]string {
	// instanceMap is a map[role arn], list of instances
	instanceMap := make(map[string][]string)
	ec2Client := ec2.New(sess)
	instanceCount := 0

	// Get name, and role of every ec2 instance
	listInstancesInput := ec2.DescribeInstancesInput{}
	instancePage, err := ec2Client.DescribeInstances(&listInstancesInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, reservation := range instancePage.Reservations {
		for _, instance := range reservation.Instances {

			// Get Name and ID
			instanceID := *instance.InstanceId
			instanceName := "<No Name Tag>"
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					instanceName = *tag.Value
					break
				}
			}

			instanceRole := ""
			if instance.IamInstanceProfile == nil {
				continue
			} else {
				instanceRole = *instance.IamInstanceProfile.Arn
				splitRole := strings.Split(instanceRole, "/")
				instanceRole = splitRole[len(splitRole)-1]
			}

			if _, ok := instanceMap[instanceRole]; ok {
				instanceMap[instanceRole] = append(instanceMap[instanceRole], fmt.Sprintf("Instance: %s (%s) via %s", instanceName, instanceID, instanceRole))
			} else {
				instanceMap[instanceRole] = []string{fmt.Sprintf("Instance: %s (%s) via %s", instanceName, instanceID, instanceRole)}
			}
			instanceCount++

		}
	}

	// Keep going until we run out of pages
	for instancePage.NextToken != nil {
		listInstancesInput = ec2.DescribeInstancesInput{
			NextToken: instancePage.NextToken,
		}
		instancePage, err = ec2Client.DescribeInstances(&listInstancesInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, reservation := range instancePage.Reservations {
			for _, instance := range reservation.Instances {
	
				// Get Name and ID
			instanceID := *instance.InstanceId
			instanceName := "<No Name Tag>"
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					instanceName = *tag.Value
					break
				}
			}

			instanceRole := ""
			if instance.IamInstanceProfile == nil {
				continue
			} else {
				instanceRole = *instance.IamInstanceProfile.Arn
				splitRole := strings.Split(instanceRole, "/")
				instanceRole = splitRole[len(splitRole)-1]
			}

			if _, ok := instanceMap[instanceRole]; ok {
				instanceMap[instanceRole] = append(instanceMap[instanceRole], fmt.Sprintf("Instance: %s (%s) via %s", instanceName, instanceID, instanceRole))
			} else {
				instanceMap[instanceRole] = []string{fmt.Sprintf("Instance: %s (%s) via %s", instanceName, instanceID, instanceRole)}
			}
			instanceCount++
	
			}
		}
	}
	log.Infof("Found %d instances", instanceCount)
	return instanceMap
}

// CheckEc2Instances ...
func CheckEc2Instances(log logger.Logger, sess client.ConfigProvider, auditList cache.Audits,
	auditResults *map[string]map[string]map[string][]string, localRoles map[string]map[string][]string, instanceMap map[string][]string) {

	// For each instance, simulate its policy
	for action, resourceMap := range localRoles {
		for resource, localRoleList := range resourceMap {
			for auditID, auditMap := range *auditResults {
				for auditAction := range auditMap {
					if auditAction != action {
						continue
					}

					for _, localRole := range localRoleList {
						for instanceRole, instanceNames := range instanceMap {
							if instanceRole != localRole {
								continue
							}
							(*auditResults)[auditID][action][resource] =
								append((*auditResults)[auditID][action][resource], instanceNames...)
						}
					}
				}
			}
		}
	}
}
