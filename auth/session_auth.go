package SessionAuth

import (
	"errors"
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/errors"
	"github.com/goravel/framework/support/database"
	"github.com/spf13/cast"
)

const (
	ctxKey = "GoravelSessionAuth"
	cookieName = "session_id"
)

type SessionAuth struct {
	config config.Config
	ctx    http.Context
	orm    orm.Orm
	sessionStore SessionStore
}

// SessionStore defines an interface for session storage (e.g., in-memory, Redis).
type SessionStore interface {
	Set(sessionID string, key string, value any, ttl time.Duration) error
	Get(sessionID string, key string) (any, error)
	Delete(sessionID string) error
}

func NewSessionAuth(config config.Config, ctx http.Context, orm orm.Orm, sessionStore SessionStore) *SessionAuth {
	return &SessionAuth{
		config:       config,
		ctx:          ctx,
		orm:          orm,
		sessionStore: sessionStore,
	}
}

func (a *SessionAuth) Guard(name string) *SessionAuth {
	return &SessionAuth{
		config:       a.config,
		ctx:          a.ctx,
		orm:          a.orm,
		sessionStore: a.sessionStore,
	}
}

func (a *SessionAuth) User(user any) error {
	sessionID, err := a.ctx.Cookie(cookieName)
	if err != nil || sessionID == "" {
		return errors.New("no active session")
	}

	userID, err := a.sessionStore.Get(sessionID, "user_id")
	if err != nil {
		return errors.New("session not found or expired")
	}

	if err := a.orm.Query().FindOrFail(user, database.Eq{Column: database.PrimaryColumn, Value: userID}); err != nil {
		return err
	}

	return nil
}

func (a *SessionAuth) ID() (string, error) {
	sessionID, err := a.ctx.Cookie(cookieName)
	if err != nil || sessionID == "" {
		return "", errors.New("no active session")
	}

	userID, err := a.sessionStore.Get(sessionID, "user_id")
	if err != nil {
		return "", errors.New("session not found or expired")
	}

	return cast.ToString(userID), nil
}

func (a *SessionAuth) Login(user any) (string, error) {
	id := database.GetID(user)
	if id == nil {
		return "", errors.New("user has no primary key field")
	}

	sessionID := a.generateSessionID()
	err := a.sessionStore.Set(sessionID, "user_id", cast.ToString(id), a.getSessionTTL())
	if err != nil {
		return "", fmt.Errorf("failed to set session: %w", err)
	}

	a.ctx.WithCookie(cookieName, sessionID, int(a.getSessionTTL().Seconds()), "/", a.config.GetString("app.domain"), false, true)
	return sessionID, nil
}

func (a *SessionAuth) Refresh() (string, error) {
	sessionID, err := a.ctx.Cookie(cookieName)
	if err != nil || sessionID == "" {
		return "", errors.New("no active session")
	}

	userID, err := a.sessionStore.Get(sessionID, "user_id")
	if err != nil {
		return "", errors.New("session not found or expired")
	}

	newSessionID := a.generateSessionID()
	err = a.sessionStore.Set(newSessionID, "user_id", userID, a.getSessionTTL())
	if err != nil {
		return "", fmt.Errorf("failed to refresh session: %w", err)
	}

	a.ctx.WithCookie(cookieName, newSessionID, int(a.getSessionTTL().Seconds()), "/", a.config.GetString("app.domain"), false, true)
	return newSessionID, nil
}

func (a *SessionAuth) Logout() error {
	sessionID, err := a.ctx.Cookie(cookieName)
	if err != nil || sessionID == "" {
		return nil
	}

	err = a.sessionStore.Delete(sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	a.ctx.WithCookie(cookieName, "", -1, "/", a.config.GetString("app.domain"), false, true)
	return nil
}

func (a *SessionAuth) generateSessionID() string {
	// Generate a unique session ID (e.g., UUID or secure random string)
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}

func (a *SessionAuth) getSessionTTL() time.Duration {
	sessionTTL := a.config.GetInt("SessionAuth.session_ttl")
	if sessionTTL == 0 {
		// Default to 24 hours
		sessionTTL = 60 * 24
	}

	return time.Duration(sessionTTL) * time.Minute
}
