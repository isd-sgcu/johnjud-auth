package cache

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type CacheRepositoryTest struct {
	suite.Suite
}

func TestCacheRepository(t *testing.T) {
	suite.Run(t, new(CacheRepositoryTest))
}

func (t *CacheRepositoryTest) SetupTest() {

}
