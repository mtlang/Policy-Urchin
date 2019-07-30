package lambda

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/lambda"

	logger "github.com/mtlang/Policy-Urchin/log"
	"github.com/mtlang/Policy-Urchin/cache"
)

// GetAllLambdaFunctions ...
func GetAllLambdaFunctions(log logger.Logger, sess client.ConfigProvider) map[string][]string {
	// functionMap is a map[role arn], list of functions
	functionMap := make(map[string][]string)
	lambdaClient := lambda.New(sess)
	functionCount := 0

	// Get name, and role of every lambda function
	listFunctionsInput := lambda.ListFunctionsInput{}
	functionPage, err := lambdaClient.ListFunctions(&listFunctionsInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, function := range functionPage.Functions {
		functionName := *function.FunctionName

		functionRole := ""
		functionRoleArn := ""
		if function.Role == nil {
			continue
		} else {
			functionRoleArn = *function.Role
			splitRole := strings.Split(*function.Role, "/")
			functionRole = splitRole[len(splitRole)-1]
		}

		if _, ok := functionMap[functionRoleArn]; ok {
			functionMap[functionRoleArn] = append(functionMap[functionRoleArn], fmt.Sprintf("Function: %s via %s", functionName, functionRole))
		} else {
			functionMap[functionRoleArn] = []string{fmt.Sprintf("Function: %s via %s", functionName, functionRole)}
		}
		functionCount++

	}

	// Keep going until we run out of pages
	for functionPage.NextMarker != nil {
		listFunctionsInput = lambda.ListFunctionsInput{
			Marker: functionPage.NextMarker,
		}
		functionPage, err = lambdaClient.ListFunctions(&listFunctionsInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, function := range functionPage.Functions {
			functionName := *function.FunctionName

			functionRole := ""
			functionRoleArn := ""
			if function.Role == nil {
				continue
			} else {
				functionRoleArn = *function.Role
				splitRole := strings.Split(*function.Role, "/")
				functionRole = splitRole[len(splitRole)-1]
			}

			if _, ok := functionMap[functionRoleArn]; ok {
				functionMap[functionRoleArn] = append(functionMap[functionRoleArn], fmt.Sprintf("Function: %s via %s", functionName, functionRole))
			} else {
				functionMap[functionRoleArn] = []string{fmt.Sprintf("Function: %s via %s", functionName, functionRole)}
			}
			functionCount++
		}
	}
	log.Infof("Found %d functions", functionCount)
	return functionMap
}

// CheckLambdaFunctions ...
func CheckLambdaFunctions(log logger.Logger, sess client.ConfigProvider, auditList cache.Audits,
	auditResults *map[string]map[string]map[string][]string, localRoles map[string]map[string][]string, functionMap map[string][]string) {

	// For each function, simulate its policy
	for action, resourceMap := range localRoles {
		for resource, localRoleList := range resourceMap {
			for auditID, auditMap := range *auditResults {
				for auditAction := range auditMap {
					if auditAction != action {
						continue
					}

					for _, localRole := range localRoleList {
						for functionRole, functionNames := range functionMap {
							splitRole := strings.Split(functionRole, "/")
							functionRole = splitRole[len(splitRole)-1]
							if functionRole != localRole {
								continue
							}
							(*auditResults)[auditID][action][resource] =
								append((*auditResults)[auditID][action][resource], functionNames...)
						}
					}
				}
			}
		}
	}
}
