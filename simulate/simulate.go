package simulate

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	iam "github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v2"

	logger "github.com/mtlang/Policy-Urchin/log"
	"github.com/mtlang/Policy-Urchin/cache"
	"github.com/mtlang/Policy-Urchin/ec2"
	"github.com/mtlang/Policy-Urchin/ecs"
	"github.com/mtlang/Policy-Urchin/lambda"
)

type fullSimulationResult struct {
	Result   *iam.SimulatePolicyResponse
	Arn      string
	AuditID  string
	Resource string
}

// Simulate ...
func Simulate(log logger.Logger, sess client.ConfigProvider) {
	// AuditResults is map[Audit ID] -> map[action] -> users that can perform the action
	auditResults := make(map[string]map[string]map[string][]string)

	// Validate and unpack audit file
	auditList := cache.Audits{}
	fileName := viper.GetString("audit-file")

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	auditBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	if strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml") {
		err = yaml.Unmarshal(auditBytes, &auditList)
	} else if strings.HasSuffix(fileName, ".json") {
		err = json.Unmarshal(auditBytes, &auditList)
	} else {
		log.Fatal("Invalid audit file. Audit file should be yaml or json.")
	}
	if err != nil {
		log.Fatal(err)
	}

	// Initialize output map
	for _, audit := range auditList.Audits {
		auditResults[audit.ID] = make(map[string]map[string][]string)
		for _, action := range audit.Actions {
			auditResults[audit.ID][action] = make(map[string][]string)
			if len(audit.Resources) == 0 {
				auditResults[audit.ID][action]["*"] = []string{}
			}
			for _, resource := range audit.Resources {
				auditResults[audit.ID][action][resource] = []string{}
			}
		}
	}

	iamClient := iam.New(sess)

	// Lambda flag
	if viper.GetBool("lambda") {
		lambdaFunctions := lambda.GetAllLambdaFunctions(log, sess)

		roleList := []string{}
		for roleArn := range lambdaFunctions {
			roleList = append(roleList, roleArn)
		}
		localRoles := simulateIamEntities(log, iamClient, roleList, auditList)

		lambda.CheckLambdaFunctions(log, sess, auditList, &auditResults, localRoles, lambdaFunctions)
	}

	// ECS flag
	if viper.GetBool("ecs") {
		ecsTasks := ecs.GetAllEcsTaskDefinitions(log, sess)

		roleList := []string{}
		for roleArn := range ecsTasks {
			roleList = append(roleList, roleArn)
		}
		localRoles := simulateIamEntities(log, iamClient, roleList, auditList)

		ecs.CheckEcsTaskDefinitions(log, sess, auditList, &auditResults, localRoles, ecsTasks)
	}

	// Get all roles with permission
	localRoles := checkAllLocalRoles(log, iamClient, auditList)

	// EC2 flag
	if viper.GetBool("ec2") {
		instanceMap := ec2.GetAllEc2Instances(log, sess)

		ec2.CheckEc2Instances(log, sess, auditList, &auditResults, localRoles, instanceMap)
	}

	if !viper.GetBool("no-users") {	
		// Get users in the account with permission
		checkLocalUsers(log, iamClient, auditList, &auditResults)

		// Get cached users with permission
		stsClient := sts.New(sess)
		identity, _ := stsClient.GetCallerIdentity(nil)
		accountNum := *identity.Account
		checkCachedRoles(log, iamClient, auditList, localRoles, &auditResults, accountNum)
	}

	outputResults(log, auditResults)
}

func checkLocalUsers(log logger.Logger, iamClient *iam.IAM, auditList cache.Audits,
	auditResults *map[string]map[string]map[string][]string) {
	// Get the ARN of every user
	listUsersInput := iam.ListUsersInput{}
	userArns := []string{}
	userPage, err := iamClient.ListUsers(&listUsersInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, user := range userPage.Users {
		userArns = append(userArns, *user.Arn)
	}
	for *userPage.IsTruncated {
		listUsersInput := iam.ListUsersInput{
			Marker: userPage.Marker,
		}
		userPage, err = iamClient.ListUsers(&listUsersInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, user := range userPage.Users {
			userArns = append(userArns, *user.Arn)
		}

	}
	log.Infof("Found %d users", len(userArns))
	retval := simulateIamEntities(log, iamClient, userArns, auditList)
	for auditID, actionMap := range *auditResults {
		for action, resourceMap := range actionMap {
			for resource, userList := range resourceMap {
				for _, user := range retval[action][resource] {
					(*auditResults)[auditID][action][resource] =
						append(userList, fmt.Sprintf("Local User: %s", user))
				}
			}
		}
	}
}

func checkAllLocalRoles(log logger.Logger, iamClient *iam.IAM, auditList cache.Audits) map[string]map[string][]string {
	// Get the ARN of every role
	listRolesInput := iam.ListRolesInput{}
	roleArns := []string{}
	rolePage, err := iamClient.ListRoles(&listRolesInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, role := range rolePage.Roles {
		if !strings.Contains(*role.Arn, "aws-service-role") {
			roleArns = append(roleArns, *role.Arn)
		}
	}
	for *rolePage.IsTruncated {
		listRolesInput := iam.ListRolesInput{
			Marker: rolePage.Marker,
		}
		rolePage, err = iamClient.ListRoles(&listRolesInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, role := range rolePage.Roles {
			if !strings.Contains(*role.Arn, "aws-service-role") {
				roleArns = append(roleArns, *role.Arn)
			}
		}

	}
	log.Infof("Found %d roles", len(roleArns))

	// Process roles
	return simulateIamEntities(log, iamClient, roleArns, auditList)
}

func simulateIamEntities(log logger.Logger, iamClient *iam.IAM, iamArns []string, auditList cache.Audits) map[string]map[string][]string {
	// retval is map[action][resources] -> arns that can perform the action on the resource
	retval := make(map[string]map[string][]string)

	resultChan := make(chan fullSimulationResult, 200)
	threadCount := 0
	maxThreads := 8

	responses := []fullSimulationResult{}
	for _, roleArn := range iamArns {
		for _, audit := range auditList.Audits {

			for threadCount >= maxThreads {
				responses = append(responses, <-resultChan)
				threadCount--
			}

			for _, resource := range audit.Resources {

				go simulatePolicy(log, iamClient, resultChan, roleArn, audit.Actions, resource, audit.ID)
				threadCount++

			}
			if len(audit.Resources) == 0 {
				go simulatePolicy(log, iamClient, resultChan, roleArn, audit.Actions, "*", audit.ID)
				threadCount++
			}
		}
	}

	for i := threadCount; i > 0; i-- {
		responses = append(responses, <-resultChan)
	}

	for _, response := range responses {
		for _, result := range response.Result.EvaluationResults {
			if strings.Contains(strings.ToLower(*result.EvalDecision), "allow") {
				log.Debugf("Role %s, Action: %s, Decision %s", response.Arn, *result.EvalActionName, *result.EvalDecision)

				roleArn := response.Arn
				roleName := roleArn[strings.LastIndex(roleArn, "/")+1:]
				resource := response.Resource

				if resourceMap, ok := retval[*result.EvalActionName]; ok {
					if roles, ok := resourceMap[resource]; ok {
						retval[*result.EvalActionName][resource] = append(roles, roleName)
					} else {
						retval[*result.EvalActionName][resource] = []string{roleName}
					}
				} else {
					retval[*result.EvalActionName] = make(map[string][]string)
					retval[*result.EvalActionName][resource] = []string{roleName}
				}
			}
		}
	}
	return retval
}

func checkCachedRoles(log logger.Logger, iamClient *iam.IAM, auditList cache.Audits, localRoles map[string]map[string][]string,
	auditResults *map[string]map[string]map[string][]string, accountNum string) {

	var cache cache.Cache
	// Load cache file
	cacheBytes, err := ioutil.ReadFile(viper.GetString("cache-file"))
	
	if err != nil {
		if strings.Contains(err.Error(), "no such file") {
			log.Infof("File: %s not found. Skipping cached users...", viper.GetString("cache-file"))
			return
		}
		log.Fatal(err)
	}
	err = json.Unmarshal(cacheBytes, &cache)

	cachedUserMap := cache.Users
	relevantRoles := cachedUserMap[accountNum]

	// Add users with permission to assume a role in any account
	for wildcardRole, wildcardUsers := range cachedUserMap["*"] {
		if relevantUsers, ok := relevantRoles[wildcardRole]; ok {
			relevantUsers = append(relevantUsers, wildcardUsers...)
		} else {
			relevantRoles[wildcardRole] = wildcardUsers
		}
	}

	for action, resourceMap := range localRoles {
		for resource, localRoleList := range resourceMap {
			for auditID, auditMap := range *auditResults {
				for auditAction := range auditMap {
					if auditAction != action {
						continue
					}
					if len(localRoleList) > 0 {
						if relevantUsers, ok := relevantRoles["*"]; ok {
							for _, user := range relevantUsers {
								(*auditResults)[auditID][action][resource] =
									append((*auditResults)[auditID][action][resource], fmt.Sprintf("%s via *", user))
							}
						}
					}
					for _, localRole := range localRoleList {
						if relevantUsers, ok := relevantRoles[localRole]; ok {
							for _, user := range relevantUsers {
								(*auditResults)[auditID][action][resource] =
									append((*auditResults)[auditID][action][resource], fmt.Sprintf("%s via %s", user, localRole))
							}
						}

					}
				}
			}
		}

	}

}

func simulatePolicy(log logger.Logger, iamClient *iam.IAM, resultChan chan fullSimulationResult,
	arn string, actions []string, resource string, auditID string) fullSimulationResult {

	if resource == "" {
		resource = "*"
	}

	simulatePrincipalPolicyInput := iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(arn),
		ActionNames:     aws.StringSlice(actions),
		ResourceArns:    aws.StringSlice([]string{resource}),
	}

	simulatePolicyOutput, err := iamClient.SimulatePrincipalPolicy(&simulatePrincipalPolicyInput)

	maxRetries := 10
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchEntity") {
			log.Infof("IAM entity %s not found", arn)
			simulatePolicyOutput = &iam.SimulatePolicyResponse{
				EvaluationResults: []*iam.EvaluationResult{
					&iam.EvaluationResult{
						EvalDecision: aws.String("Deny"),
					},
				},
			}
		} else if !strings.Contains(err.Error(), "Throttling") && !strings.Contains(err.Error(), "RequestError") {
			log.Infof("arn: %s\nactions: %s", arn, actions)
			log.Fatal(err)
		}
		for i := 1; i <= maxRetries; i++ {
			time.Sleep(time.Millisecond * 600 * time.Duration(i))
			simulatePolicyOutput, err = iamClient.SimulatePrincipalPolicy(&simulatePrincipalPolicyInput)
			if err == nil {
				break
			}
		}
		if err != nil {
			if strings.Contains(err.Error(), "NoSuchEntity") {
				log.Infof("IAM entity %s not found", arn)
				simulatePolicyOutput = &iam.SimulatePolicyResponse{
					EvaluationResults: []*iam.EvaluationResult{
						&iam.EvaluationResult{
							EvalDecision: aws.String("Deny"),
						},
					},
				}
			} else {
				log.Info("Max retries reached while attempting to simulate policy.")
				log.Fatal(err)
			}
		}
	}

	retval := fullSimulationResult{
		Result:   simulatePolicyOutput,
		Arn:      arn,
		AuditID:  auditID,
		Resource: resource,
	}

	resultChan <- retval
	return retval
}

// Reviews results in auditResults. Checks services for resource-specific policies (S3 bucket policy, SQS queue policy, etc.).
// If any acccess is denied by a resource policy, remove it from auditResults.
func checkForResourcePolicies(log logger.Logger, iamClient *iam.IAM, auditResults *map[string]map[string]map[string][]string) {

	servicesToCheck := []string{"s3"}

	//auditResults[audit.ID][action][resource]
	for auditID, actionMap := range *auditResults {
		for action, resourceMap := range actionMap {

			// If the action isn't for a service we need to check, skip it
			toCheck := ""
			for _, serviceToCheck := range servicesToCheck {
				if strings.HasPrefix(action, serviceToCheck) {
					toCheck = serviceToCheck
					break
				}
			}
			if toCheck == "" {
				continue
			}

			// If we get here, we need to check the action
			for resource, users := range resourceMap {
				// Get the policy
				policy := getResourcePolicy(log, resource)

				for _, user := range users {
					arn := user
					if strings.Contains(arn, " via ") {
						splitUser := strings.Split(arn, " via ")
						arn = splitUser[1]
						if arn == "*" {
							continue
						}
					}

					// Simulate again with resource policy
					simulateResult := simulatePolicyWithResourcePolicy(log, iamClient, arn, action, resource, auditID, policy)
					log.Info(simulateResult)
				}

			}
		}
	}
}

func getResourcePolicy(log logger.Logger, arn string) string {
	resourcePolicy := ""
	splitArn := strings.Split(arn, ":")
	service := splitArn[2]
	if service == "s3" {
		resourcePolicy = getS3Policy(log, arn)
	}

	return resourcePolicy
}

func getS3Policy(log logger.Logger, arn string) string {
	bucketPolicy := ""

	// Get name of bucket
	bucketName := arn[strings.LastIndex(arn, ":")+1 : strings.Index(arn, "/")]
	sess, err := session.NewSession(nil)
	if err != nil {
		log.Fatal(err)
	}
	s3Client := s3.New(sess)

	getPolicyInput := s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	}

	response, err := s3Client.GetBucketPolicy(&getPolicyInput)
	if err != nil {
		log.Fatal(err)
	}

	bucketPolicy = *response.Policy

	return bucketPolicy
}

func simulatePolicyWithResourcePolicy(log logger.Logger, iamClient *iam.IAM,
	arn string, action string, resource string, auditID string, policy string) fullSimulationResult {

	if resource == "" {
		resource = "*"
	}

	actions := []string{action}

	simulatePrincipalPolicyInput := iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(arn),
		ActionNames:     aws.StringSlice(actions),
		ResourceArns:    aws.StringSlice([]string{resource}),
	}

	simulatePolicyOutput, err := iamClient.SimulatePrincipalPolicy(&simulatePrincipalPolicyInput)

	maxRetries := 10
	if err != nil {
		if !strings.Contains(err.Error(), "Throttling") {
			log.Infof("arn: %s\nactions: %s", arn, actions)
			log.Fatal(err)
		}
		for i := 1; i <= maxRetries; i++ {
			time.Sleep(time.Millisecond * 400 * time.Duration(i))
			simulatePolicyOutput, err = iamClient.SimulatePrincipalPolicy(&simulatePrincipalPolicyInput)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Fatal("Max retries reached while attempting to simulate policy.")
		}
	}

	retval := fullSimulationResult{
		Result:   simulatePolicyOutput,
		Arn:      arn,
		AuditID:  auditID,
		Resource: resource,
	}

	return retval
}

func outputResults(log logger.Logger, auditResultsMap map[string]map[string]map[string][]string) {
	output := ""

	for auditID, actionMap := range auditResultsMap {
		output += auditID + ":\n"
		for action, resourceMap := range actionMap {
			output += fmt.Sprintf("  %s: \n", action)
			for resource, users := range resourceMap {
				if resource == "*" {
					resource = `"*"`
				}

				userString := strings.Join(users, "\n      - ")
				if len(userString) == 0 {
					output += fmt.Sprintf("    %s: \n", resource)
				} else {
					output += fmt.Sprintf("    %s: \n      - %s\n", resource, userString)
				}

			}
		}
	}
	outBytes := []byte(output)

	outputFileName := viper.GetString("output")
	if outputFileName == "" {
		fmt.Print(output)
	} else {
		file, err := os.Create(outputFileName)
		if err != nil {
			log.Fatal(err)
		}
		_, err = file.Write(outBytes)
		if err != nil {
			panic(err)
		}
		log.Infof("Wrote output to %s", outputFileName)
	}
}
