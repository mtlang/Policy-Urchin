package cache

// Cache ...
type Cache struct {
	Policies   	map[string]map[string][]string           `json:"Policies" yaml:"policies"`
	Groups 		map[string]map[string][]string           `json:"Groups" yaml:"groups"`
	Users    	map[string]map[string][]string           `json:"Users" yaml:"users"`
}

// Audits ...
type Audits struct {
	Audits []struct {
		ID          string   `json:"ID" yaml:"id"`
		Description string   `json:"Description" yaml:"description"`
		Actions     []string `json:"Actions" yaml:"actions"`
		Resources   []string `json:"Resources" yaml:"resources"`
	}
}

// AuditResults ...
type AuditResults struct {
	AuditResults []struct {
		ID      string
		Actions map[string][]string
	}
}