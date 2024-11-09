package processors

import (
	"strings"

	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/support/collect"
)

type Sqlite struct {
}

func NewSqlite() Sqlite {
	return Sqlite{}
}

func (r Sqlite) ProcessIndexes(dbIndexes []DBIndex) []schema.Index {
	var (
		indexes      []schema.Index
		primaryCount int
	)
	for _, dbIndex := range dbIndexes {
		if dbIndex.Primary {
			primaryCount++
		}

		indexes = append(indexes, schema.Index{
			Columns: strings.Split(dbIndex.Columns, ","),
			Name:    strings.ToLower(dbIndex.Name),
			Primary: dbIndex.Primary,
			Unique:  dbIndex.Unique,
		})
	}

	if primaryCount > 1 {
		indexes = collect.Filter(indexes, func(index schema.Index, _ int) bool {
			return !index.Primary
		})
	}

	return indexes
}
