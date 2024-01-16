package cfgldr

import (
	"github.com/spf13/viper"
)

type Database struct {
	Url string `mapstructure:"URL"`
}

type App struct {
	Port   int    `mapstructure:"PORT"`
	Env    string `mapstructure:"ENV"`
	Secret string `mapstructure:"SECRET"`
}

type Jwt struct {
	Secret          string `mapstructure:"SECRET"`
	ExpiresIn       int    `mapstructure:"EXPIRES_IN"`
	RefreshTokenTTL int    `mapstructure:"REFRESH_TOKEN_TTL"`
	Issuer          string `mapstructure:"ISSUER"`
	ResetTokenTTL   int    `mapstructure:"RESET_TOKEN_TTL"`
}

type Redis struct {
	Host     string `mapstructure:"HOST"`
	Port     int    `mapstructure:"PORT"`
	Password string `mapstructure:"PASSWORD"`
}

type Auth struct {
	ClientURL string `mapstructure:"CLIENT_URL"`
}

type Sendgrid struct {
	ApiKey  string `mapstructure:"API_KEY"`
	Name    string `mapstructure:"NAME"`
	Address string `mapstructure:"ADDRESS"`
}

type Config struct {
	App      App
	Database Database
	Jwt      Jwt
	Redis    Redis
	Auth     Auth
	Sendgrid Sendgrid
}

func LoadConfig() (*Config, error) {
	dbConfig := Database{}
	LoadEnvGroup(&dbConfig, "DB")

	appConfig := App{}
	LoadEnvGroup(&appConfig, "APP")

	jwtConfig := &Jwt{}
	LoadEnvGroup(jwtConfig, "JWT")

	redisConfig := &Redis{}
	LoadEnvGroup(redisConfig, "REDIS")

	authConfig := &Auth{}
	LoadEnvGroup(authConfig, "AUTH")

	sendgridConfig := &Sendgrid{}
	LoadEnvGroup(sendgridConfig, "SENDGRID")

	config := &Config{
		Database: dbConfig,
		App:      appConfig,
		Jwt:      *jwtConfig,
		Redis:    *redisConfig,
		Auth:     *authConfig,
		Sendgrid: *sendgridConfig,
	}

	return config, nil
}

func (ac *App) IsDevelopment() bool {
	return ac.Env == "development"
}

func LoadEnvGroup(config interface{}, prefix string) (err error) {
	cfgLdr := viper.New()
	cfgLdr.SetEnvPrefix(prefix)
	cfgLdr.AutomaticEnv()
	cfgLdr.AllowEmptyEnv(false)
	if err := cfgLdr.Unmarshal(&config); err != nil {
		return err
	}
	return nil
}
