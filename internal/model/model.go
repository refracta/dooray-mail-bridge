// Package model defines the provider-independent mailbox contract.
package model

import (
	"context"
	"errors"
	"time"
)

var ErrUnsupported = errors.New("operation is not supported by this provider")
var ErrAuthentication = errors.New("authentication failed")
var ErrUnavailable = errors.New("mail provider unavailable")
var ErrNotFound = errors.New("mailbox or message not found")

type Folder struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SpecialUse string `json:"specialUse,omitempty"`
}

type Message struct {
	ID    string    `json:"id"`
	Date  time.Time `json:"date"`
	Flags []string  `json:"flags"`
	Size  int64     `json:"size"`
	// Subject is decoded provider metadata, used to avoid downloading bodies
	// and attachments just to evaluate a nonempty SUBJECT search. Nil means
	// unknown; an empty string is distinct from an unknown value.
	Subject *string `json:"subject,omitempty"`
}

// Provider operations must return errors rather than report unperformed writes
// as successful. Raw returns original RFC 5322 bytes without marking mail read.
type Provider interface {
	Authenticate(context.Context, string, string) error
	Folders(context.Context) ([]Folder, error)
	Messages(context.Context, string) ([]Message, error)
	Raw(context.Context, string) ([]byte, error)
	SetFlags(context.Context, string, []string) error
	Move(context.Context, []string, string) error
	Copy(context.Context, []string, string) error
	Delete(context.Context, []string) error
	CreateFolder(context.Context, string) (Folder, error)
	RenameFolder(context.Context, string, string) error
	DeleteFolder(context.Context, string) error
	Append(context.Context, string, []byte, []string, time.Time) (string, error)
	Send(context.Context, string, []string, []byte) error
}
