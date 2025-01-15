package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cast"
	"gorm.io/gorm/clause"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/cache"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/errors"
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

func (s *SessionAuth) User(user any) error {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return errors.AuthInvalidSession
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
		return "", errors.AuthInvalidSession
	}

	userID, err := s.getUserIDFromSession(sessionID)
	if err != nil {
		return "", err
	}

	return userID, nil
}

func (s *SessionAuth) Login(user any) (string, error) {
	id := database.GetID(user) // Получаем ID пользователя
	if id == nil {
		return "", errors.AuthNoPrimaryKeyField
	}

	return s.LoginUsingID(id)
}

func (s *SessionAuth) LoginUsingID(id any) (string, error) {
	sessionID := s.generateSessionID()
	userID := cast.ToString(id)
	if userID == "" {
		return "", errors.AuthInvalidKey
	}

	ttl := time.Duration(s.getSessionTTL()) * time.Minute
	if err := s.cache.Put(sessionKey+sessionID, userID, ttl); err != nil {
		return "", err
	}

	// Устанавливаем cookie с sessionID
	s.ctx.WithCookie(&http.Cookie{
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

	// Удаляем cookie
	s.ctx.WithCookie(&http.Cookie{
		Name:   sessionKey,
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Удаляем cookie
	})

	return nil
}

func (s *SessionAuth) Refresh() (string, error) {
	sessionID := s.getSessionID()
	if sessionID == "" {
		return "", errors.AuthInvalidSession
	}

	userID, err := s.getUserIDFromSession(sessionID)
	if err != nil {
		return "", err
	}

	// Генерируем новый sessionID и обновляем TTL
	newSessionID := s.generateSessionID()
	ttl := time.Duration(s.getSessionTTL()) * time.Minute
	if err := s.cache.Put(sessionKey+newSessionID, userID, ttl); err != nil {
		return "", err
	}

	// Устанавливаем новый sessionID в cookie
	s.ctx.WithCookie(&http.Cookie{
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
	if !s.cache.Get(sessionKey+sessionID, &userID) || userID == "" {
		return "", errors.AuthInvalidSession
	}

	return userID, nil
}

func (s *SessionAuth) generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (s *SessionAuth) getSessionTTL() int {
	ttl := s.config.GetInt(fmt.Sprintf("auth.guards.%s.ttl", s.guard))
	if ttl == 0 {
		ttl = 60 // Default TTL: 60 минут
	}

	return ttl
}
