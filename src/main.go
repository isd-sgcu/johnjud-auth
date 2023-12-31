package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/database"
	"github.com/isd-sgcu/johnjud-auth/src/internal/strategy"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	authRp "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/auth"
	cacheRp "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/cache"
	userRp "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	authSvc "github.com/isd-sgcu/johnjud-auth/src/pkg/service/auth"
	jwtSvc "github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	tokenSvc "github.com/isd-sgcu/johnjud-auth/src/pkg/service/token"
	userSvc "github.com/isd-sgcu/johnjud-auth/src/pkg/service/user"
	authPb "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	userPb "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/user/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type operation func(ctx context.Context) error

func gracefulShutdown(ctx context.Context, timeout time.Duration, ops map[string]operation) <-chan struct{} {
	wait := make(chan struct{})
	go func() {
		s := make(chan os.Signal, 1)

		signal.Notify(s, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
		sig := <-s

		log.Info().
			Str("service", "graceful shutdown").
			Msgf("got signal \"%v\" shutting down service", sig)

		timeoutFunc := time.AfterFunc(timeout, func() {
			log.Error().
				Str("service", "graceful shutdown").
				Msgf("timeout %v ms has been elapsed, force exit", timeout.Milliseconds())
			os.Exit(0)
		})

		defer timeoutFunc.Stop()

		var wg sync.WaitGroup

		for key, op := range ops {
			wg.Add(1)
			innerOp := op
			innerKey := key
			go func() {
				defer wg.Done()

				log.Info().
					Str("service", "graceful shutdown").
					Msgf("cleaning up: %v", innerKey)
				if err := innerOp(ctx); err != nil {
					log.Error().
						Str("service", "graceful shutdown").
						Err(err).
						Msgf("%v: clean up failed: %v", innerKey, err.Error())
					return
				}

				log.Info().
					Str("service", "graceful shutdown").
					Msgf("%v was shutdown gracefully", innerKey)
			}()
		}

		wg.Wait()
		close(wait)
	}()

	return wait
}

func main() {
	conf, err := config.LoadConfig()
	if err != nil {
		log.Fatal().
			Err(err).
			Str("service", "auth").
			Msg("Failed to load config")
	}

	db, err := database.InitPostgresDatabase(&conf.Database, conf.App.Debug)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("service", "auth").
			Msg("Failed to init postgres connection")
	}

	cacheDb, err := database.InitRedisConnection(&conf.Redis)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("service", "auth").
			Msg("Failed to init redis connection")
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", conf.App.Port))
	if err != nil {
		log.Fatal().
			Err(err).
			Str("service", "auth").
			Msg("Failed to start service")
	}

	grpcServer := grpc.NewServer()

	jwtUtil := utils.NewJwtUtil()
	uuidUtil := utils.NewUuidUtil()
	bcryptUtil := utils.NewBcryptUtil()

	authRepo := authRp.NewRepository(db)
	userRepo := userRp.NewRepository(db)

	userService := userSvc.NewService(userRepo, bcryptUtil)

	accessTokenCache := cacheRp.NewRepository(cacheDb)
	refreshTokenCache := cacheRp.NewRepository(cacheDb)

	jwtStrategy := strategy.NewJwtStrategy(conf.Jwt.Secret)
	jwtService := jwtSvc.NewService(conf.Jwt, jwtStrategy, jwtUtil)
	tokenService := tokenSvc.NewService(jwtService, accessTokenCache, refreshTokenCache, uuidUtil)

	authService := authSvc.NewService(authRepo, userRepo, tokenService, bcryptUtil)

	grpc_health_v1.RegisterHealthServer(grpcServer, health.NewServer())
	authPb.RegisterAuthServiceServer(grpcServer, authService)
	userPb.RegisterUserServiceServer(grpcServer, userService)

	reflection.Register(grpcServer)
	go func() {
		log.Info().
			Str("service", "auth").
			Msgf("JohnJud auth starting at port %v", conf.App.Port)

		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal().
				Err(err).
				Str("service", "auth").
				Msg("Failed to start service")
		}
	}()

	wait := gracefulShutdown(context.Background(), 2*time.Second, map[string]operation{
		"server": func(ctx context.Context) error {
			grpcServer.GracefulStop()
			return nil
		},
		"database": func(ctx context.Context) error {
			sqlDB, err := db.DB()
			if err != nil {
				return nil
			}
			return sqlDB.Close()
		},
		"cache": func(ctx context.Context) error {
			return cacheDb.Close()
		},
	})

	<-wait

	grpcServer.GracefulStop()
	log.Info().
		Str("service", "auth").
		Msg("Closing the listener")
	lis.Close()
	log.Info().
		Str("service", "auth").
		Msg("End the program")
}
