package email

import (
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/email"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type serviceImpl struct {
	config cfgldr.Sendgrid
	client *sendgrid.Client
}

func (s *serviceImpl) SendEmail(subject string, toName string, toAddress string, content string) error {
	from := mail.NewEmail(s.config.Name, s.config.Address)
	to := mail.NewEmail(toName, toAddress)
	message := mail.NewSingleEmail(from, subject, to, content, content)

	_, err := s.client.Send(message)
	if err != nil {
		return err
	}
	return nil
}

func NewService(config cfgldr.Sendgrid) email.Service {
	client := sendgrid.NewSendClient(config.ApiKey)
	return &serviceImpl{config: config, client: client}
}
