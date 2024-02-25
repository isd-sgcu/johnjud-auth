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
	dbCfgLdr := viper.New()
	dbCfgLdr.SetEnvPrefix("DB")
	dbCfgLdr.AutomaticEnv()
	dbCfgLdr.AllowEmptyEnv(false)
	dbConfig := Database{}
	if err := dbCfgLdr.Unmarshal(&dbConfig); err != nil {
		return nil, err
	}

	appCfgLdr := viper.New()
	appCfgLdr.SetEnvPrefix("APP")
	appCfgLdr.AutomaticEnv()
	appCfgLdr.AllowEmptyEnv(false)
	appConfig := App{}
	if err := appCfgLdr.Unmarshal(&appConfig); err != nil {
		return nil, err
	}

	jwtCfgLdr := viper.New()
	jwtCfgLdr.SetEnvPrefix("JWT")
	jwtCfgLdr.AutomaticEnv()
	jwtCfgLdr.AllowEmptyEnv(false)
	jwtConfig := Jwt{}
	if err := jwtCfgLdr.Unmarshal(&jwtConfig); err != nil {
		return nil, err
	}

	redisCfgLdr := viper.New()
	redisCfgLdr.SetEnvPrefix("REDIS")
	redisCfgLdr.AutomaticEnv()
	redisCfgLdr.AllowEmptyEnv(false)
	redisConfig := Redis{}
	if err := redisCfgLdr.Unmarshal(&redisConfig); err != nil {
		return nil, err
	}

	authCfgLdr := viper.New()
	authCfgLdr.SetEnvPrefix("AUTH")
	authCfgLdr.AutomaticEnv()
	authCfgLdr.AllowEmptyEnv(false)
	authConfig := Auth{}
	if err := authCfgLdr.Unmarshal(&authConfig); err != nil {
		return nil, err
	}

	sendgridCfgLdr := viper.New()
	sendgridCfgLdr.SetEnvPrefix("SENDGRID")
	sendgridCfgLdr.AutomaticEnv()
	sendgridCfgLdr.AllowEmptyEnv(false)
	sendgridConfig := Sendgrid{}
	if err := sendgridCfgLdr.Unmarshal(&sendgridConfig); err != nil {
		return nil, err
	}

	config := &Config{
		Database: dbConfig,
		App:      appConfig,
		Jwt:      jwtConfig,
		Redis:    redisConfig,
		Auth:     authConfig,
		Sendgrid: sendgridConfig,
	}

	return config, nil
}

func (ac *App) IsDevelopment() bool {
	return ac.Env == "development"
}
