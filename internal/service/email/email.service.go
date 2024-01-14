package email

import (
	"fmt"
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/email"
	"github.com/pkg/errors"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"net/http"
)

type serviceImpl struct {
	config cfgldr.Sendgrid
	client *sendgrid.Client
}

func (s *serviceImpl) SendEmail(subject string, toName string, toAddress string, content string) error {
	from := mail.NewEmail(s.config.Name, s.config.Address)
	to := mail.NewEmail(toName, toAddress)
	message := mail.NewSingleEmail(from, subject, to, content, content)

	resp, err := s.client.Send(message)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted {
		return errors.New(fmt.Sprintf("%d status code", resp.StatusCode))
	}

	return nil
}

func NewService(config cfgldr.Sendgrid) email.Service {
	client := sendgrid.NewSendClient(config.ApiKey)
	return &serviceImpl{config: config, client: client}
}
