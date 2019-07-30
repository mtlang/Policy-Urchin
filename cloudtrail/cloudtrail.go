package cloudtrail

// FullEvent ...
type FullEvent struct {
	EventVersion string
    UserIdentity struct {
        Type string
        PrincipalID string
        Arn string
        AccountID string
        UserName string
    }
    EventTime string
    EventSource string
    EventName string
    AwsRegion string
    SourceIPAddress string
    UserAgent string
    RequestParameters string
    ResponseElements struct {
        ConsoleLogin string
    }
    AdditionalEventData struct {
        LoginTo string
        MobileVersion string
        MFAUsed string
    }
    EventID string
    EventType string
    RecipientAccountID string
}