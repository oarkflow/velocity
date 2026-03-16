package doclib

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const (
	orgCompanyPrefix    = "org:company:"
	orgDeptPrefix       = "org:dept:"
	orgUnitPrefix       = "org:unit:"
	orgObjectivePrefix  = "org:objective:"
	orgUseCasePrefix    = "org:usecase:"
	orgMembershipPrefix = "org:membership:"
)

// Company represents a top-level organisational entity.
type Company struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	Active      bool      `json:"active"`
}

// Department is a subdivision of a Company.
type Department struct {
	ID         string    `json:"id"`
	CompanyID  string    `json:"company_id"`
	Name       string    `json:"name"`
	Code       string    `json:"code"`
	HeadUserID string    `json:"head_user_id"`
	CreatedAt  time.Time `json:"created_at"`
	Active     bool      `json:"active"`
}

// Unit is a subdivision of a Department.
type Unit struct {
	ID            string    `json:"id"`
	DeptID        string    `json:"dept_id"`
	CompanyID     string    `json:"company_id"`
	Name          string    `json:"name"`
	Code          string    `json:"code"`
	ManagerUserID string    `json:"manager_user_id"`
	CreatedAt     time.Time `json:"created_at"`
	Active        bool      `json:"active"`
}

// Objective is associated with a Unit.
type Objective struct {
	ID          string    `json:"id"`
	UnitID      string    `json:"unit_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	DueDate     time.Time `json:"due_date"`
	Status      string    `json:"status"`
}

// UseCase is associated with a Unit.
type UseCase struct {
	ID          string   `json:"id"`
	UnitID      string   `json:"unit_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

// Membership records a user's membership in a unit.
type Membership struct {
	UserID    string    `json:"user_id"`
	UnitID    string    `json:"unit_id"`
	DeptID    string    `json:"dept_id"`
	CompanyID string    `json:"company_id"`
	Role      string    `json:"role"` // member | manager | head
	JoinedAt  time.Time `json:"joined_at"`
	Active    bool      `json:"active"`
}

// OrgManager handles org-hierarchy CRUD.
type OrgManager struct {
	db *velocity.DB
}

// NewOrgManager returns an OrgManager backed by the given DB.
func NewOrgManager(db *velocity.DB) *OrgManager {
	return &OrgManager{db: db}
}

// ---- Company ----

func (m *OrgManager) CreateCompany(name, description, createdBy string) (*Company, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: name required", ErrInvalidInput)
	}
	c := &Company{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
		Active:      true,
	}
	return c, m.put(orgCompanyPrefix+c.ID, c)
}

func (m *OrgManager) GetCompany(id string) (*Company, error) {
	var c Company
	return &c, m.get(orgCompanyPrefix+id, &c)
}

func (m *OrgManager) ListCompanies() ([]*Company, error) {
	keys, err := m.db.Keys(orgCompanyPrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]*Company, 0, len(keys))
	for _, k := range keys {
		var c Company
		if err := m.get(k, &c); err == nil {
			out = append(out, &c)
		}
	}
	return out, nil
}

// ---- Department ----

func (m *OrgManager) CreateDepartment(companyID, name, code, headUserID, createdBy string) (*Department, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(companyID) == "" {
		return nil, fmt.Errorf("%w: name and companyID required", ErrInvalidInput)
	}
	d := &Department{
		ID:         uuid.NewString(),
		CompanyID:  companyID,
		Name:       name,
		Code:       code,
		HeadUserID: headUserID,
		CreatedAt:  time.Now().UTC(),
		Active:     true,
	}
	return d, m.put(orgDeptPrefix+d.ID, d)
}

func (m *OrgManager) GetDepartment(id string) (*Department, error) {
	var d Department
	return &d, m.get(orgDeptPrefix+id, &d)
}

func (m *OrgManager) ListDepartments(companyID string) ([]*Department, error) {
	keys, err := m.db.Keys(orgDeptPrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]*Department, 0)
	for _, k := range keys {
		var d Department
		if err := m.get(k, &d); err == nil {
			if companyID == "" || d.CompanyID == companyID {
				out = append(out, &d)
			}
		}
	}
	return out, nil
}

// ---- Unit ----

func (m *OrgManager) CreateUnit(deptID, companyID, name, code, managerUserID string) (*Unit, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(deptID) == "" {
		return nil, fmt.Errorf("%w: name and deptID required", ErrInvalidInput)
	}
	u := &Unit{
		ID:            uuid.NewString(),
		DeptID:        deptID,
		CompanyID:     companyID,
		Name:          name,
		Code:          code,
		ManagerUserID: managerUserID,
		CreatedAt:     time.Now().UTC(),
		Active:        true,
	}
	return u, m.put(orgUnitPrefix+u.ID, u)
}

func (m *OrgManager) GetUnit(id string) (*Unit, error) {
	var u Unit
	return &u, m.get(orgUnitPrefix+id, &u)
}

func (m *OrgManager) ListUnits(deptID string) ([]*Unit, error) {
	keys, err := m.db.Keys(orgUnitPrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]*Unit, 0)
	for _, k := range keys {
		var u Unit
		if err := m.get(k, &u); err == nil {
			if deptID == "" || u.DeptID == deptID {
				out = append(out, &u)
			}
		}
	}
	return out, nil
}

// ---- Membership ----

func (m *OrgManager) AddMember(userID, unitID, role string) (*Membership, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(unitID) == "" {
		return nil, fmt.Errorf("%w: userID and unitID required", ErrInvalidInput)
	}
	unit, err := m.GetUnit(unitID)
	if err != nil {
		return nil, fmt.Errorf("unit not found: %w", ErrNotFound)
	}
	if role == "" {
		role = "member"
	}
	mem := &Membership{
		UserID:    userID,
		UnitID:    unitID,
		DeptID:    unit.DeptID,
		CompanyID: unit.CompanyID,
		Role:      role,
		JoinedAt:  time.Now().UTC(),
		Active:    true,
	}
	key := fmt.Sprintf("%s%s:%s", orgMembershipPrefix, userID, unitID)
	return mem, m.put(key, mem)
}

func (m *OrgManager) RemoveMember(userID, unitID string) error {
	key := fmt.Sprintf("%s%s:%s", orgMembershipPrefix, userID, unitID)
	var mem Membership
	if err := m.get(key, &mem); err != nil {
		return ErrNotFound
	}
	mem.Active = false
	return m.put(key, &mem)
}

func (m *OrgManager) GetMemberships(userID string) ([]*Membership, error) {
	pattern := fmt.Sprintf("%s%s:*", orgMembershipPrefix, userID)
	keys, err := m.db.Keys(pattern)
	if err != nil {
		return nil, err
	}
	out := make([]*Membership, 0, len(keys))
	for _, k := range keys {
		var mem Membership
		if err := m.get(k, &mem); err == nil && mem.Active {
			out = append(out, &mem)
		}
	}
	return out, nil
}

// GetMembership returns the membership record for userID in unitID.
func (m *OrgManager) GetMembership(userID, unitID string) (*Membership, error) {
	key := fmt.Sprintf("%s%s:%s", orgMembershipPrefix, userID, unitID)
	var mem Membership
	if err := m.get(key, &mem); err != nil {
		return nil, ErrNotFound
	}
	return &mem, nil
}

// IsManagerOrHead returns true if the user is manager of the unit or head of the dept.
func (m *OrgManager) IsManagerOrHead(userID, unitID string) bool {
	unit, err := m.GetUnit(unitID)
	if err != nil {
		return false
	}
	if unit.ManagerUserID == userID {
		return true
	}
	dept, err := m.GetDepartment(unit.DeptID)
	if err != nil {
		return false
	}
	return dept.HeadUserID == userID
}

// ListUnitMembers returns all active memberships for a given unit.
func (m *OrgManager) ListUnitMembers(unitID string) ([]*Membership, error) {
	keys, err := m.db.Keys(orgMembershipPrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]*Membership, 0)
	for _, k := range keys {
		var mem Membership
		if err := m.get(k, &mem); err == nil && mem.Active && mem.UnitID == unitID {
			out = append(out, &mem)
		}
	}
	return out, nil
}

// ListAllUsers returns all unique user IDs from active memberships.
func (m *OrgManager) ListAllUsers() ([]string, error) {
	keys, err := m.db.Keys(orgMembershipPrefix + "*")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, k := range keys {
		var mem Membership
		if err := m.get(k, &mem); err == nil && mem.Active {
			seen[mem.UserID] = struct{}{}
		}
	}
	users := make([]string, 0, len(seen))
	for u := range seen {
		users = append(users, u)
	}
	return users, nil
}

// ---- helpers ----

func (m *OrgManager) put(key string, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.db.Put([]byte(key), b)
}

func (m *OrgManager) get(key string, v interface{}) error {
	b, err := m.db.Get([]byte(key))
	if err != nil {
		return ErrNotFound
	}
	return json.Unmarshal(b, v)
}
