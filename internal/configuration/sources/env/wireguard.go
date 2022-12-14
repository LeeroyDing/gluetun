package env

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
)

func (s *Source) readWireguard() (wireguard settings.Wireguard, err error) {
	defer func() {
		err = unsetEnvKeys([]string{"WIREGUARD_PRIVATE_KEY", "WIREGUARD_PRESHARED_KEY"}, err)
	}()
	wireguard.PrivateKey = envToStringPtr("WIREGUARD_PRIVATE_KEY")
	wireguard.PreSharedKey = envToStringPtr("WIREGUARD_PRESHARED_KEY")
	_, wireguard.Interface = s.getEnvWithRetro("VPN_INTERFACE", "WIREGUARD_INTERFACE")
	wireguard.Implementation = os.Getenv("WIREGUARD_IMPLEMENTATION")
	wireguard.AllowedIPs, err = s.readWireguardAllowedIPs()
	if err != nil {
		return wireguard, err // already wrapped
	}
	wireguard.Addresses, err = s.readWireguardAddresses()
	if err != nil {
		return wireguard, err // already wrapped
	}
	return wireguard, nil
}

func (s *Source) readWireguardAllowedIPs() (allowedIPs []net.IPNet, err error) {
	allowedIPStrings := envToCSV("WIREGUARD_ALLOWED_IPS")
	if len(allowedIPStrings) == 0 {
		return nil, nil
	}

	allowedIPs = make([]net.IPNet, len(allowedIPStrings))
	for i, addressString := range allowedIPStrings {
		addressString = strings.TrimSpace(addressString)
		ip, ipNet, err := net.ParseCIDR(addressString)
		if err != nil {
			return nil, fmt.Errorf("environment variable WIREGUARD_ALLOWED_IPS: %w", err)
		}
		ipNet.IP = ip
		allowedIPs[i] = *ipNet
	}

	return allowedIPs, nil
}

func (s *Source) readWireguardAddresses() (addresses []net.IPNet, err error) {
	key, addressesCSV := s.getEnvWithRetro("WIREGUARD_ADDRESSES", "WIREGUARD_ADDRESS")
	if addressesCSV == "" {
		return nil, nil
	}

	addressStrings := strings.Split(addressesCSV, ",")
	addresses = make([]net.IPNet, len(addressStrings))
	for i, addressString := range addressStrings {
		addressString = strings.TrimSpace(addressString)
		ip, ipNet, err := net.ParseCIDR(addressString)
		if err != nil {
			return nil, fmt.Errorf("environment variable %s: %w", key, err)
		}
		ipNet.IP = ip
		addresses[i] = *ipNet
	}

	return addresses, nil
}
