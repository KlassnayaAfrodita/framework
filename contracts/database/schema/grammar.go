package schema

type Grammar interface {
	// CompileAdd Compile an add column command.
	CompileAdd(blueprint Blueprint, command *Command) string
	// CompileChange Compile a change column command.
	CompileChange(blueprint Blueprint, command *Command) []string
	// CompileColumns Compile the query to determine the columns.
	CompileColumns(schema, table string) string
	// CompileComment Compile a column comment command.
	CompileComment(blueprint Blueprint, command *Command) string
	// CompileCreate Compile a create table command.
	CompileCreate(blueprint Blueprint) string
	// CompileDefault Compile a default value command.
	CompileDefault(blueprint Blueprint, command *Command) string
	// CompileDrop Compile a drop table command.
	CompileDrop(blueprint Blueprint) string
	// CompileDropAllDomains Compile the SQL needed to drop all domains.
	CompileDropAllDomains(domains []string) string
	// CompileDropAllTables Compile the SQL needed to drop all tables.
	CompileDropAllTables(tables []string) string
	// CompileDropAllTypes Compile the SQL needed to drop all types.
	CompileDropAllTypes(types []string) string
	// CompileDropAllViews Compile the SQL needed to drop all views.
	CompileDropAllViews(views []string) string
	// CompileDropColumn Compile a drop column command.
	CompileDropColumn(blueprint Blueprint, command *Command) []string
	// CompileDropForeign Compile a drop foreign key command.
	CompileDropForeign(blueprint Blueprint, command *Command) string
	// CompileDropFullText Compile a drop fulltext index command.
	CompileDropFullText(blueprint Blueprint, command *Command) string
	// CompileDropIfExists Compile a drop table (if exists) command.
	CompileDropIfExists(blueprint Blueprint) string
	// CompileDropIndex Compile a drop index command.
	CompileDropIndex(blueprint Blueprint, command *Command) string
	// CompileDropPrimary Compile a drop primary key command.
	CompileDropPrimary(blueprint Blueprint, command *Command) string
	// CompileDropUnique Compile a drop unique key command.
	CompileDropUnique(blueprint Blueprint, command *Command) string
	// CompileForeign Compile a foreign key command.
	CompileForeign(blueprint Blueprint, command *Command) string
	// CompileForeignKeys Compile the query to determine the foreign keys.
	CompileForeignKeys(schema, table string) string
	// CompileFullText Compile a fulltext index key command.
	CompileFullText(blueprint Blueprint, command *Command) string
	// CompileIndex Compile a plain index key command.
	CompileIndex(blueprint Blueprint, command *Command) string
	// CompileIndexes Compile the query to determine the indexes.
	CompileIndexes(schema, table string) string
	// CompilePrimary Compile a primary key command.
	CompilePrimary(blueprint Blueprint, command *Command) string
	// CompileRename Compile a rename table command.
	CompileRename(blueprint Blueprint, command *Command) string
	// CompileRenameIndex Compile a rename index command.
	CompileRenameIndex(schema Schema, blueprint Blueprint, command *Command) []string
	// CompileTables Compile the query to determine the tables.
	CompileTables(database string) string
	// CompileTypes Compile the query to determine the types.
	CompileTypes() string
	// CompileUnique Compile a unique key command.
	CompileUnique(blueprint Blueprint, command *Command) string
	// CompileViews Compile the query to determine the views.
	CompileViews(database string) string
	// GetAttributeCommands Get the commands for the schema build.
	GetAttributeCommands() []string
	// TypeBigInteger Create the column definition for a big integer type.
	TypeBigInteger(column ColumnDefinition) string
	// TypeChar Create the column definition for a char type.
	TypeChar(column ColumnDefinition) string
	// TypeDate Create the column definition for a date type.
	TypeDate(column ColumnDefinition) string
	// TypeDateTime Create the column definition for a date-time type.
	TypeDateTime(column ColumnDefinition) string
	// TypeDateTimeTz Create the column definition for a date-time (with time zone) type.
	TypeDateTimeTz(column ColumnDefinition) string
	// TypeDecimal Create the column definition for a decimal type.
	TypeDecimal(column ColumnDefinition) string
	// TypeDouble Create the column definition for a double type.
	TypeDouble(column ColumnDefinition) string
	// TypeEnum Create the column definition for an enumeration type.
	TypeEnum(column ColumnDefinition) string
	// TypeFloat Create the column definition for a float type.
	TypeFloat(column ColumnDefinition) string
	// TypeInteger Create the column definition for an integer type.
	TypeInteger(column ColumnDefinition) string
	// TypeJson Create the column definition for a json type.
	TypeJson(column ColumnDefinition) string
	// TypeJsonb Create the column definition for a jsonb type.
	TypeJsonb(column ColumnDefinition) string
	// TypeLongText Create the column definition for a long text type.
	TypeLongText(column ColumnDefinition) string
	// TypeMediumInteger Create the column definition for a medium integer type.
	TypeMediumInteger(column ColumnDefinition) string
	// TypeMediumText Create the column definition for a medium text type.
	TypeMediumText(column ColumnDefinition) string
	// TypeText Create the column definition for a text type.
	TypeText(column ColumnDefinition) string
	// TypeTime Create the column definition for a time type.
	TypeTime(column ColumnDefinition) string
	// TypeTimeTz Create the column definition for a time (with time zone) type.
	TypeTimeTz(column ColumnDefinition) string
	// TypeTimestamp Create the column definition for a timestamp type.
	TypeTimestamp(column ColumnDefinition) string
	// TypeTimestampTz Create the column definition for a timestamp (with time zone) type.
	TypeTimestampTz(column ColumnDefinition) string
	// TypeTinyInteger Create the column definition for a tiny integer type.
	TypeTinyInteger(column ColumnDefinition) string
	// TypeTinyText Create the column definition for a tiny text type.
	TypeTinyText(column ColumnDefinition) string
	// TypeSmallInteger Create the column definition for a small integer type.
	TypeSmallInteger(column ColumnDefinition) string
	// TypeString Create the column definition for a string type.
	TypeString(column ColumnDefinition) string
}
