package auth

import (
	"fmt"
	"time"

	"github.com/spf13/cast"
	"gorm.io/gorm/clause"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/cache"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/errors"
	"github.com/goravel/framework/support/database"
)

const sessionCtxKey = "GoravelAuth"

type Session struct {
	SessionID string
}

type Sessions map[string]*Session

type SessionAuth struct {
	cache  cache.Cache
	config config.Config
	ctx    http.Context
	session  string
	orm    orm.Orm
}

func NewSessionAuth(session string, cache cache.Cache, config config.Config, ctx http.Context, orm orm.Orm) *Auth {
	return &Auth{
		cache:  cache,
		config: config,
		ctx:    ctx,
		session:  session,
		orm:    orm,
	}
}

func (a *SessionAuth) Session(name string) contractsauth.Auth {
	return NewAuth(name, a.cache, a.config, a.ctx, a.orm)
}

func (a *SessionAuth) SessionUser(user any) error {
	auth, ok := a.ctx.Value(ctxKey).(Sessions)
	if !ok || auth[a.session] == nil {
		return errors.AuthParseSessionFirst
	}
	if auth[a.session].SessionID == "" {
		return errors.AuthInvalidSession
	}

	if err := a.orm.Query().FindOrFail(user, clause.Eq{Column: clause.PrimaryColumn, Value: auth[a.Session].SessionID}); err != nil {
		return err
	}

	return nil
}

func (a *SessionAuth) SessionID() (string, error) {
	auth, ok := a.ctx.Value(ctxKey).(Sessions)
	if !ok || auth[a.session] == nil {
		return "", errors.AuthParseSessionFirst
	}
	if auth[a.session].SessionID == "" {
		return "", errors.AuthInvalidSession
	}

	return auth[a.session].SessionID, nil
}

func (a *SessionAuth) SessionLogin(user any) (string, error) {
	id := database.GetID(user)
	if id == nil {
		return "", errors.AuthNoPrimaryKeyField
	}

	sessionID := cast.ToString(id)
	if sessionID == "" {
		return "", errors.AuthInvalidSessionID
	}

	if err := a.cache.Put(getSessionCacheKey(sessionID), true, time.Duration(a.getSessionTtl())*time.Minute); err != nil {
		return "", err
	}

	a.makeAuthContext(sessionID)

	return sessionID, nil
}

func (a *SessionAuth) SessionLogout() error {
	auth, ok := a.ctx.Value(ctxKey).(Sessions)
	if !ok || auth[a.session] == nil || auth[a.session].SessionID == "" {
		return nil
	}

	if err := a.cache.Forget(getSessionCacheKey(auth[a.Session].SessionID)); err != nil {
		return err
	}

	delete(auth, a.Session)
	a.ctx.WithValue(ctxKey, auth)

	return nil
}

func (a *SessionAuth) SessionRefresh() (string, error) {
	auth, ok := a.ctx.Value(ctxKey).(Sessions)
	if !ok || auth[a.session] == nil {
		return "", errors.AuthParseSessionFirst
	}

	if !a.cache.GetBool(getSessionCacheKey(auth[a.Session].SessionID), false) {
		return "", errors.AuthSessionExpired
	}

	return auth[a.session].SessionID, nil
}

func (a *Auth) makeSessionAuthContext(sessionID string) {
	Sessions, ok := a.ctx.Value(ctxKey).(Sessions)
	if !ok {
		Sessions = make(Sessions)
	}
	Sessions[a.session] = &Session{SessionID: sessionID}
	a.ctx.WithValue(ctxKey, Sessions)
}

func (a *SessionAuth) getSessionTtl() int {
	var ttl int
	SessionTtl := a.config.Get(fmt.Sprintf("auth.Sessions.%s.ttl", a.Session))
	if SessionTtl == nil {
		ttl = a.config.GetInt("session.ttl")
	} else {
		ttl = cast.ToInt(SessionTtl)
	}

	if ttl == 0 {
		// Default to 30 days
		tl = 60 * 24 * 30
	}

	return ttl
}

func getSessionCacheKey(sessionID string) string {
	return "session:" + sessionID
}
