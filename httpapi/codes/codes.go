package codes

// Success200 OK
// swagger:model
type Success200 struct {
	// Status text
	Status string `json:"status" example:"ok"`
}

// Error400 Bad Request
// swagger:model
type Error400 struct {
	// Error text
	Error string `json:"error" example:"Bad Request"`
}

// Error405 Method Not Allowed
// swagger:model
type Error405 struct {
	// Error text
	Error string `json:"error" example:"method not allowed"`
}

// Error500 Internal Server Error
// swagger:model
type Error500 struct {
	// Error text
	Error string `json:"error" example:"Internal Server Error"`
}
