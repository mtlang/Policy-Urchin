package ecs

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ecs"

	logger "github.com/mtlang/Policy-Urchin/log"
	"github.com/mtlang/Policy-Urchin/cache"
)

// GetAllEcsTaskDefinitions ...
func GetAllEcsTaskDefinitions(log logger.Logger, sess client.ConfigProvider) map[string][]string {
	// taskMap is a map[role arn], list of tasks
	taskMap := make(map[string][]string)
	ecsClient := ecs.New(sess)
	taskCount := 0

	// Get name, and role of every ecs task
	listTaskDefinitionsInput := ecs.ListTaskDefinitionsInput{}
	taskPage, err := ecsClient.ListTaskDefinitions(&listTaskDefinitionsInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, taskArn := range taskPage.TaskDefinitionArns {
		describeTaskDefinitionInput := ecs.DescribeTaskDefinitionInput{
			TaskDefinition: taskArn,
		}
		describeTaskDefinitionOutput, err := ecsClient.DescribeTaskDefinition(&describeTaskDefinitionInput)
		if err != nil {
			log.Fatal(err)
		}
		task := describeTaskDefinitionOutput.TaskDefinition
		taskName := fmt.Sprintf("%s:%d", *task.Family, *task.Revision)

		taskRole := ""
		taskRoleArn := ""
		if task.TaskRoleArn == nil {
			continue
		} else {
			taskRoleArn = *task.TaskRoleArn
			splitRole := strings.Split(taskRoleArn, "/")
			taskRole = splitRole[len(splitRole)-1]
		}

		if _, ok := taskMap[taskRoleArn]; ok {
			taskMap[taskRoleArn] = append(taskMap[taskRoleArn], fmt.Sprintf("Task: %s via %s", taskName, taskRole))
		} else {
			taskMap[taskRoleArn] = []string{fmt.Sprintf("Task: %s via %s", taskName, taskRole)}
		}
		taskCount++

	}

	// Keep going until we run out of pages
	for taskPage.NextToken != nil {
		listTaskDefinitionsInput = ecs.ListTaskDefinitionsInput{
			NextToken: taskPage.NextToken,
		}
		taskPage, err = ecsClient.ListTaskDefinitions(&listTaskDefinitionsInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, taskArn := range taskPage.TaskDefinitionArns {
			describeTaskDefinitionInput := ecs.DescribeTaskDefinitionInput{
				TaskDefinition: taskArn,
			}
			describeTaskDefinitionOutput, err := ecsClient.DescribeTaskDefinition(&describeTaskDefinitionInput)
			if err != nil {
				log.Fatal(err)
			}
			task := describeTaskDefinitionOutput.TaskDefinition
			taskName := fmt.Sprintf("%s:%d", *task.Family, *task.Revision)
	
			taskRole := ""
			taskRoleArn := ""
			if task.TaskRoleArn == nil {
				continue
			} else {
				taskRoleArn = *task.TaskRoleArn
				splitRole := strings.Split(taskRoleArn, "/")
				taskRole = splitRole[len(splitRole)-1]
			}
	
			if _, ok := taskMap[taskRoleArn]; ok {
				taskMap[taskRoleArn] = append(taskMap[taskRoleArn], fmt.Sprintf("Task: %s via %s", taskName, taskRole))
			} else {
				taskMap[taskRoleArn] = []string{fmt.Sprintf("Task: %s via %s", taskName, taskRole)}
			}
			taskCount++
	
		}
	}
	log.Infof("Found %d tasks", taskCount)
	return taskMap
}

// CheckEcsTaskDefinitions ...
func CheckEcsTaskDefinitions(log logger.Logger, sess client.ConfigProvider, auditList cache.Audits,
	auditResults *map[string]map[string]map[string][]string, localRoles map[string]map[string][]string, taskMap map[string][]string) {

	// For each task, simulate its policy
	for action, resourceMap := range localRoles {
		for resource, localRoleList := range resourceMap {
			for auditID, auditMap := range *auditResults {
				for auditAction := range auditMap {
					if auditAction != action {
						continue
					}

					for _, localRole := range localRoleList {
						for taskRole, taskNames := range taskMap {
							splitRole := strings.Split(taskRole, "/")
							taskRole = splitRole[len(splitRole)-1]
							if taskRole != localRole {
								continue
							}
							(*auditResults)[auditID][action][resource] =
								append((*auditResults)[auditID][action][resource], taskNames...)
						}
					}
				}
			}
		}
	}
}
