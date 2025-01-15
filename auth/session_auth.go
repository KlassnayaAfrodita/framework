package auth

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/cache"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/errors"
	"github.com/goravel/framework/support/carbon"
	"github.com/spf13/cast"
)

const sessionKey = "GoravelAuthSession"

type SessionAuth struct {
	cache  cache.Cache
	config config.Config
	ctx    http.Context
	guard  string
	orm    orm.Orm
}

func NewSessionAuth(guard string, cache cache.Cache, config config.Config, ctx http.Context, orm orm.Orm) *SessionAuth {
	return &SessionAuth{
		cache:  cache,
		config: config,
		ctx:    ctx,
		guard:  guard,
		orm:    orm,
	}
}

func (s *SessionAuth) Guard(name string) auth.Auth {
	return NewSessionAuth(name, s.cache, s.config, s.ctx, s.orm)
}

func (s *SessionAuth) User(user any) error {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return errors.AuthInvalidSession
	}

	sessionData, err := s.getSessionData(sessionID)
	if err != nil {
		return err
	}

	if err := s.orm.Query().FindOrFail(user, sessionData.UserID); err != nil {
		return err
	}

	return nil
}

func (s *SessionAuth) ID() (string, error) {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return "", errors.AuthInvalidSession
	}

	sessionData, err := s.getSessionData(sessionID)
	if err != nil {
		return "", err
	}

	return sessionData.UserID, nil
}

func (s *SessionAuth) Login(user any) (string, error) {
	userID := cast.ToString(database.GetID(user))
	if userID == "" {
		return "", errors.AuthNoPrimaryKeyField
	}

	sessionID := s.generateSessionID()
	expiresAt := carbon.Now().AddMinutes(s.getSessionTTL()).StdTime()

	sessionData := &SessionData{
		UserID:    userID,
		ExpiresAt: expiresAt,
	}

	if err := s.cache.Put(sessionKey+sessionID, sessionData, time.Until(expiresAt)); err != nil {
		return "", err
	}

	s.ctx.SetCookie(&http.Cookie{
		Name:    sessionKey,
		Value:   sessionID,
		Expires: expiresAt,
		Path:    "/",
	})

	return sessionID, nil
}

func (s *SessionAuth) Logout() error {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return nil
	}

	if err := s.cache.Forget(sessionKey + sessionID); err != nil {
		return err
	}

	s.ctx.SetCookie(&http.Cookie{
		Name:   sessionKey,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	return nil
}

func (s *SessionAuth) Refresh() (string, error) {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return "", errors.AuthInvalidSession
	}

	sessionData, err := s.getSessionData(sessionID)
	if err != nil {
		return "", err
	}

	expiresAt := carbon.Now().AddMinutes(s.getSessionTTL()).StdTime()
	sessionData.ExpiresAt = expiresAt

	if err := s.cache.Put(sessionKey+sessionID, sessionData, time.Until(expiresAt)); err != nil {
		return "", err
	}

	s.ctx.SetCookie(&http.Cookie{
		Name:    sessionKey,
		Value:   sessionID,
		Expires: expiresAt,
		Path:    "/",
	})

	return sessionID, nil
}

func (s *SessionAuth) getSessionID() string {
	cookie, err := s.ctx.Cookie(sessionKey)
	if err != nil {
		return ""
	}
	return cookie
}

func (s *SessionAuth) getSessionData(sessionID string) (*SessionData, error) {
	var sessionData SessionData
	if err := s.cache.Get(sessionKey+sessionID, &sessionData); err != nil {
		return nil, errors.AuthSessionExpired
	}

	if carbon.Now().Gt(carbon.FromStdTime(sessionData.ExpiresAt)) {
		return nil, errors.AuthSessionExpired
	}

	return &sessionData, nil
}

func (s *SessionAuth) generateSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}

func (s *SessionAuth) getSessionTTL() int {
	sessionTTL := s.config.GetInt("auth.session_ttl")
	if sessionTTL == 0 {
		// Default session TTL: 30 minutes
		sessionTTL = 30
	}

	return sessionTTL
}

type SessionData struct {
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
