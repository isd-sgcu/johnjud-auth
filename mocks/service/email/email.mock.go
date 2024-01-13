package email

import "github.com/stretchr/testify/mock"

type EmailServiceMock struct {
	mock.Mock
}

func (m *EmailServiceMock) SendEmail(subject string, toName string, toAddress string, content string) error {
	args := m.Called(subject, toName, toAddress, content)
	return args.Error(0)
}
