package env

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gosettings/sources/env"
	"github.com/qdm12/govalid/binary"
)

func (s *Source) readControlServer() (controlServer settings.ControlServer, err error) {
	controlServer.Log, err = readControlServerLog()
	if err != nil {
		return controlServer, err
	}

	controlServer.Address = s.readControlServerAddress()

	return controlServer, nil
}

func readControlServerLog() (enabled *bool, err error) {
	s := env.Get("HTTP_CONTROL_SERVER_LOG")
	log, err := binary.Validate(s)
	if err != nil {
		return nil, fmt.Errorf("environment variable HTTP_CONTROL_SERVER_LOG: %w", err)
	}
	return log, nil
}

func (s *Source) readControlServerAddress() (address *string) {
	key, value := s.getEnvWithRetro("HTTP_CONTROL_SERVER_ADDRESS",
		[]string{"CONTROL_SERVER_ADDRESS"})
	if value == "" {
		return nil
	}

	if key == "HTTP_CONTROL_SERVER_ADDRESS" {
		return &value
	}

	address = new(string)
	*address = ":" + value
	return address
}
