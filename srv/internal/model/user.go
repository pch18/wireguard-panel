package model

type UserRole string

const (
	UserRoleAdmin UserRole = "admin"
)

type User struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Role     UserRole `json:"role"`
}
