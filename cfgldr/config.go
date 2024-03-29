package cfgldr

import (
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type Database struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSL      string `mapstructure:"ssl"`
}

type App struct {
	Port   int    `mapstructure:"port"`
	Debug  bool   `mapstructure:"debug"`
	Secret string `mapstructure:"secret"`
}

type Jwt struct {
	Secret          string `mapstructure:"secret"`
	ExpiresIn       int    `mapstructure:"expires_in"`
	RefreshTokenTTL int    `mapstructure:"refresh_token_ttl"`
	Issuer          string `mapstructure:"issuer"`
}

type Redis struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	Dbnum    int    `mapstructure:"dbnum"`
}

type Config struct {
	App      App      `mapstructure:"app"`
	Database Database `mapstructure:"database"`
	Jwt      Jwt      `mapstructure:"jwt"`
	Redis    Redis    `mapstructure:"redis"`
}

func LoadConfig() (config *Config, err error) {
	viper.AddConfigPath("./config")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error occurs while reading the config")
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, errors.Wrap(err, "error occurs while unmarshal the config")
	}

	return
}
