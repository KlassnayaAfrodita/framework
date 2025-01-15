package auth

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/cast"
	"gorm.io/gorm/clause"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/cache"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/support/database"
	"github.com/goravel/framework/contracts/http"
)

// Ошибки
var (
	ErrAuthInvalidSession   = errors.New("invalid session")
	ErrAuthNoPrimaryKeyField = errors.New("no primary key field found")
	ErrAuthInvalidKey       = errors.New("invalid key")
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

func (s *SessionAuth) Guard(name string) contractsauth.Auth {
	return NewSessionAuth(name, s.cache, s.config, s.ctx, s.orm)
}

func (s *SessionAuth) Parse(token string) (any, error) {
	return nil, errors.New("method Parse is not implemented for session authentication")
}

func (s *SessionAuth) User(user any) error {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return ErrAuthInvalidSession
	}

	userID, err := s.getUserIDFromSession(sessionID)
	if err != nil {
		return err
	}

	if err := s.orm.Query().FindOrFail(user, clause.Eq{Column: clause.PrimaryColumn, Value: userID}); err != nil {
		return err
	}

	return nil
}

func (s *SessionAuth) ID() (string, error) {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return "", ErrAuthInvalidSession
	}

	userID, err := s.getUserIDFromSession(sessionID)
	if err != nil {
		return "", err
	}

	return userID, nil
}

func (s *SessionAuth) Login(user any) (string, error) {
	id := database.GetID(user)
	if id == nil {
		return "", ErrAuthNoPrimaryKeyField
	}

	return s.LoginUsingID(id)
}

func (s *SessionAuth) LoginUsingID(id any) (string, error) {
	sessionID := s.generateSessionID()
	userID := cast.ToString(id)
	if userID == "" {
		return "", ErrAuthInvalidKey
	}

	ttl := time.Duration(s.getSessionTTL()) * time.Minute
	if err := s.cache.Put(sessionKey+sessionID, userID, ttl); err != nil {
		return "", err
	}

	s.ctx.Response().SetCookie(&http.Cookie{
		Name:    sessionKey,
		Value:   sessionID,
		Expires: time.Now().Add(ttl),
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

	s.ctx.Response().SetCookie(&http.Cookie{
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
		return "", ErrAuthInvalidSession
	}

	userID, err := s.getUserIDFromSession(sessionID)
	if err != nil {
		return "", err
	}

	newSessionID := s.generateSessionID()
	ttl := time.Duration(s.getSessionTTL()) * time.Minute
	if err := s.cache.Put(sessionKey+newSessionID, userID, ttl); err != nil {
		return "", err
	}

	s.ctx.Response().SetCookie(&http.Cookie{
		Name:    sessionKey,
		Value:   newSessionID,
		Expires: time.Now().Add(ttl),
		Path:    "/",
	})

	return newSessionID, nil
}

// Вспомогательные методы

func (s *SessionAuth) getSessionID() string {
	cookie, err := s.ctx.Request().Cookie(sessionKey)
	if err != nil || cookie == nil {
		return ""
	}

	return strings.TrimSpace(cookie.Value)
}

func (s *SessionAuth) getUserIDFromSession(sessionID string) (string, error) {
	var userID string
	if !s.cache.Get(sessionKey+sessionID, &userID) {
		return "", ErrAuthInvalidSession
	}

	return userID, nil
}

func (s *SessionAuth) generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (s *SessionAuth) getSessionTTL() int {
	ttl := s.config.GetInt(fmt.Sprintf("auth.guards.%s.ttl", s.guard))
	if ttl == 0 {
		ttl = 60
	}

	return ttl
}
