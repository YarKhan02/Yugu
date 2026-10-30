// Its own module so the parent build never compiles it; the analyzer loads it
// by path. No external dependencies — database/sql is stdlib.
module sessionterm

go 1.26
