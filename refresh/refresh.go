package refresh

import (
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/spf13/viper"

	logger "github.com/mtlang/Policy-Urchin/log"
	"github.com/mtlang/Policy-Urchin/cache"
)

// PolicyDocument an IAM policy document
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

// StatementEntry and IAM policy statement
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource []string
}

// Refresh ...
func Refresh(log logger.Logger, sess client.ConfigProvider) {
	var cache cache.Cache

	log.Info("Enumerating Policies...")
	policyMap := checkPolicies(log, sess)
	cache.Policies = policyMap

	log.Info("Enumerating Groups...")
	groupMap := checkGroups(log, sess, policyMap)
	cache.Groups = groupMap

	log.Info("Enumerating Users...")
	userMap := checkUsers(log, sess, groupMap)
	cache.Users = userMap

	cacheBytes, err := json.Marshal(cache)
	if err != nil {
		log.Error(err)
	}

	fileName := viper.GetString("cache-file")
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	_, err = file.Write(cacheBytes)
	if err != nil {
		panic(err)
	}
	log.Infof("Wrote cache file to %s", fileName)

}

func checkPolicies(log logger.Logger, sess client.ConfigProvider) map[string]map[string][]string {
	policyMap := make(map[string]map[string][]string)
	iamClient := iam.New(sess)

	// Get the ARN of every policy
	listPoliciesInput := iam.ListPoliciesInput{}
	policyArns := []string{}
	policyPage, err := iamClient.ListPolicies(&listPoliciesInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, policy := range policyPage.Policies {
		policyArns = append(policyArns, *policy.Arn)
	}
	for *policyPage.IsTruncated {
		listPolicicesInput := iam.ListPoliciesInput{
			Marker: policyPage.Marker,
		}
		policyPage, err = iamClient.ListPolicies(&listPolicicesInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, policy := range policyPage.Policies {
			// Skip the policy if it's aws managed
			if !strings.Contains(*policy.Arn, "aws:policy") {
				policyArns = append(policyArns, *policy.Arn)
			}
		}
	}

	log.Infof("Found %d policies", len(policyArns))

	log.Infof("Finding roles in each policy...")
	// For each policy, find each role it can assume
	for _, policyArn := range policyArns {
		// Get versions
		listPolicyVersionsInput := iam.ListPolicyVersionsInput{
			PolicyArn: aws.String(policyArn),
		}

		output, err := iamClient.ListPolicyVersions(&listPolicyVersionsInput)
		if err != nil {
			log.Fatal(err)
		}

		// Find default version
		var defaultVersionID string
		foundDefault := false
		for _, version := range output.Versions {
			if *version.IsDefaultVersion {
				foundDefault = true
				defaultVersionID = *version.VersionId
				break
			}
		}
		if !foundDefault {
			log.Fatalf("Default policy version not found for %s", policyArn)
		}

		getPolicyVersionInput := iam.GetPolicyVersionInput{
			PolicyArn: aws.String(policyArn),
			VersionId: aws.String(defaultVersionID),
		}
		defaultVersion, err := iamClient.GetPolicyVersion(&getPolicyVersionInput)
		if err != nil {
			log.Fatal(err)
		}

		policyDocumentString, err := url.PathUnescape(*defaultVersion.PolicyVersion.Document)
		if err != nil {
			log.Fatal(err)
		}

		assumableRoles := getRolesForPolicy(log, policyDocumentString)

		for _, role := range assumableRoles {
			var account, policyName, roleName string
			policyName = policyArn[strings.LastIndex(policyArn, "/")+1:]

			if role == "*" {
				account = "*"
				roleName = "*"
			} else if string(role[13]) == "*" {
				account = "*"
				roleName = role[strings.LastIndex(role, "/")+1:]
			} else {
				account = role[13:25]
				roleName = role[strings.LastIndex(role, "/")+1:]
			}

			if _, ok := policyMap[policyName]; !ok {
				policyMap[policyName] = make(map[string][]string)
			}

			if roleList, ok := policyMap[policyName][account]; ok {
				policyMap[policyName][account] = append(roleList, roleName)
			} else {
				policyMap[policyName][account] = []string{roleName}
			}
		}

	}

	log.Info("Done enumerating policies")

	return policyMap
}

func getRolesForPolicy(log logger.Logger, policyDocumentString string) []string {
	assumableRoles := []string{}

	// Skip the policy if it doesn't mention assuming a role
	if !strings.Contains(policyDocumentString, "sts:AssumeRole") {
		return assumableRoles
	}

	originalDocumentString := policyDocumentString
	// Change Statement from object to array
	re := regexp.MustCompile(`"Statement": {[\s\S]*?}`)
	match := re.FindString(policyDocumentString)
	replacement := strings.Replace(match, "{", "[{", 1)
	replacement = strings.Replace(replacement, "}", "}]", 1)
	policyDocumentString = strings.Replace(policyDocumentString, match, replacement, 1)

	// Change action from string to array
	re = regexp.MustCompile(`"Action":[^\[\]]*?"(.*?)"`)
	originals := re.FindAllString(policyDocumentString, -1)

	for _, match = range originals {
		temp := strings.Split(match, "\"")
		temp[2] = temp[2] + "["
		temp[4] = "]" + temp[4]
		replacement := strings.Join(temp, "\"")
		policyDocumentString = strings.Replace(policyDocumentString, match, replacement, -1)
	}

	// Change resource from string to array
	re = regexp.MustCompile(`"Resource":[^\[\]]*?"(.*?)"`)
	originals = re.FindAllString(policyDocumentString, -1)

	for _, match = range originals {
		temp := strings.Split(match, "\"")
		temp[2] = temp[2] + "["
		temp[4] = "]" + temp[4]
		replacement := strings.Join(temp, "\"")
		policyDocumentString = strings.Replace(policyDocumentString, match, replacement, -1)
	}

	// Unmarshall into struct
	var policyDocument PolicyDocument
	err := json.Unmarshal([]byte(policyDocumentString), &policyDocument)
	if err != nil {
		log.Info(originalDocumentString)
		log.Info(policyDocumentString)
		log.Fatal(err)
	}

	for _, statement := range policyDocument.Statement {
		for _, action := range statement.Action {
			if action == "sts:AssumeRole" {
				for _, role := range statement.Resource {
					assumableRoles = append(assumableRoles, role)
				}
			}
		}
	}

	return assumableRoles
}

func checkGroups(log logger.Logger, sess client.ConfigProvider,
	policyMap map[string]map[string][]string) map[string]map[string][]string {

	groupMap := make(map[string]map[string][]string)

	iamClient := iam.New(sess)

	// Get the ARN of every group
	listGroupsInput := iam.ListGroupsInput{}
	groupNames := []string{}
	groupPage, err := iamClient.ListGroups(&listGroupsInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, group := range groupPage.Groups {
		groupNames = append(groupNames, *group.GroupName)
	}
	for *groupPage.IsTruncated {
		listGroupsInput := iam.ListGroupsInput{
			Marker: groupPage.Marker,
		}
		groupPage, err = iamClient.ListGroups(&listGroupsInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, group := range groupPage.Groups {
			groupNames = append(groupNames, *group.GroupName)
		}

	}

	log.Infof("Found %d groups", len(groupNames))

	for _, groupName := range groupNames {
		// Process attached policies
		listAttachedGroupPoliciesInput := iam.ListAttachedGroupPoliciesInput{
			GroupName: aws.String(groupName),
		}
		listAttachedGroupPoliciesOutput, err := iamClient.ListAttachedGroupPolicies(&listAttachedGroupPoliciesInput)
		if err != nil {
			log.Info(groupName)
			log.Fatal(err)
		}

		for _, attachedPolicy := range listAttachedGroupPoliciesOutput.AttachedPolicies {
			// Map[account] -> list of roles
			accountsMap := policyMap[*attachedPolicy.PolicyName]

			for account, roles := range accountsMap {
				if _, ok := groupMap[groupName]; !ok {
					groupMap[groupName] = make(map[string][]string)
				}

				if roleList, ok := groupMap[groupName][account]; ok {
					groupMap[groupName][account] = append(roleList, roles...)
				} else {
					groupMap[groupName][account] = roles
				}
			}
		}

		// Process inline policies
		listGroupPoliciesInput := iam.ListGroupPoliciesInput{
			GroupName: aws.String(groupName),
		}
		listGroupPoliciesOutput, err := iamClient.ListGroupPolicies(&listGroupPoliciesInput)
		if err != nil {
			log.Info(groupName)
			log.Fatal(err)
		}

		for _, inlinePolicyName := range listGroupPoliciesOutput.PolicyNames {
			getGroupPolicyInput := iam.GetGroupPolicyInput{
				GroupName:  aws.String(groupName),
				PolicyName: inlinePolicyName,
			}
			getGroupPolicyOutput, err := iamClient.GetGroupPolicy(&getGroupPolicyInput)
			if err != nil {
				log.Fatal(err)
			}

			policyDocumentString, err := url.PathUnescape(*getGroupPolicyOutput.PolicyDocument)
			if err != nil {
				log.Fatal(err)
			}
			assumableRoles := getRolesForPolicy(log, policyDocumentString)

			for _, role := range assumableRoles {
				var account, roleName string

				if role == "*" {
					account = "*"
					roleName = "*"
				} else if string(role[13]) == "*" {
					account = "*"
					roleName = role[strings.LastIndex(role, "/")+1:]
				} else {
					account = role[13:25]
					roleName = role[strings.LastIndex(role, "/")+1:]
				}

				if _, ok := groupMap[groupName]; !ok {
					groupMap[groupName] = make(map[string][]string)
				}

				if roleList, ok := groupMap[groupName][account]; ok {
					groupMap[groupName][account] = append(roleList, roleName)
				} else {
					groupMap[groupName][account] = []string{roleName}
				}
			}
		}

	}

	return groupMap
}

func checkUsers(log logger.Logger, sess client.ConfigProvider,
	groupMap map[string]map[string][]string) map[string]map[string][]string {

	userMap := make(map[string]map[string][]string)

	iamClient := iam.New(sess)

	// Get the name of every user
	listUsersInput := iam.ListUsersInput{}
	userNames := []string{}
	userPage, err := iamClient.ListUsers(&listUsersInput)
	if err != nil {
		log.Fatal(err)
	}

	for _, user := range userPage.Users {
		userNames = append(userNames, *user.UserName)
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
			userNames = append(userNames, *user.UserName)
		}

	}

	log.Infof("Found %d users", len(userNames))

	// Note: This only looks at attached groups. It assumes that no users have policies directly attached.
	for _, userName := range userNames {
		listGroupsForUserInput := iam.ListGroupsForUserInput{
			UserName: aws.String(userName),
		}
		listGroupsForUserOutput, err := iamClient.ListGroupsForUser(&listGroupsForUserInput)
		if err != nil {
			log.Info(userName)
			log.Fatal(err)
		}

		for _, group := range listGroupsForUserOutput.Groups {
			// Map[account] -> list of roles
			accountsMap := groupMap[*group.GroupName]

			for account, roles := range accountsMap {
				for _, role := range roles {
					if _, ok := userMap[account]; !ok {
						userMap[account] = make(map[string][]string)
					}
	
					if userList, ok := userMap[account][role]; ok {
						userMap[account][role] = append(userList, userName)
					} else {
						userMap[account][role] = []string{userName}
					}
				}
				
			}
		}

	}

	return userMap
}
