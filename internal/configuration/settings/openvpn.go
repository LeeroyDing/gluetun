package settings

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/openvpn/extract"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// OpenVPN contains settings to configure the OpenVPN client.
type OpenVPN struct {
	// Version is the OpenVPN version to run.
	// It can only be "2.5" or "2.6".
	Version string
	// User is the OpenVPN authentication username.
	// It cannot be nil in the internal state if OpenVPN is used.
	// It is usually required but in some cases can be the empty string
	// to indicate no user+password authentication is needed.
	User *string
	// Password is the OpenVPN authentication password.
	// It cannot be nil in the internal state if OpenVPN is used.
	// It is usually required but in some cases can be the empty string
	// to indicate no user+password authentication is needed.
	Password *string
	// ConfFile is a custom OpenVPN configuration file path.
	// It can be set to the empty string for it to be ignored.
	// It cannot be nil in the internal state.
	ConfFile *string
	// Ciphers is a list of ciphers to use for OpenVPN,
	// different from the ones specified by the VPN
	// service provider configuration files.
	Ciphers []string
	// Auth is an auth algorithm to use in OpenVPN instead
	// of the one specified by the VPN service provider.
	// It cannot be nil in the internal state.
	// It is ignored if it is set to the empty string.
	Auth *string
	// Cert is the base64 encoded DER of an OpenVPN certificate for the <cert> block.
	// This is notably used by Cyberghost and VPN secure.
	// It can be set to the empty string to be ignored.
	// It cannot be nil in the internal state.
	Cert *string
	// Key is the base64 encoded DER of an OpenVPN key.
	// This is used by Cyberghost and VPN Unlimited.
	// It can be set to the empty string to be ignored.
	// It cannot be nil in the internal state.
	Key *string
	// EncryptedKey is the base64 encoded DER of an encrypted key for OpenVPN.
	// It is used by VPN secure.
	// It defaults to the empty string meaning it is not
	// to be used. KeyPassphrase must be set if this one is set.
	EncryptedKey *string
	// KeyPassphrase is the key passphrase to be used by OpenVPN
	// to decrypt the EncryptedPrivateKey. It defaults to the
	// empty string and must be set if EncryptedPrivateKey is set.
	KeyPassphrase *string
	// PIAEncPreset is the encryption preset for
	// Private Internet Access. It can be set to an
	// empty string for other providers.
	PIAEncPreset *string
	// MSSFix is the value (1 to 10000) to set for the
	// mssfix option for OpenVPN. It is ignored if set to 0.
	// It cannot be nil in the internal state.
	MSSFix *uint16
	// Interface is the OpenVPN device interface name.
	// It cannot be an empty string in the internal state.
	Interface string
	// ProcessUser is the OpenVPN process OS username
	// to use. It cannot be empty in the internal state.
	// It defaults to 'root'.
	ProcessUser string
	// Verbosity is the OpenVPN verbosity level from 0 to 6.
	// It cannot be nil in the internal state.
	Verbosity *int
	// Flags is a slice of additional flags to be passed
	// to the OpenVPN program.
	Flags []string
}

var ivpnAccountID = regexp.MustCompile(`^(i|ivpn)\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{4}$`)

func (o OpenVPN) validate(vpnProvider string) (err error) {
	// Validate version
	validVersions := []string{openvpn.Openvpn25, openvpn.Openvpn26}
	if err = validate.IsOneOf(o.Version, validVersions...); err != nil {
		return fmt.Errorf("%w: %w", ErrOpenVPNVersionIsNotValid, err)
	}

	isCustom := vpnProvider == providers.Custom
	isUserRequired := !isCustom &&
		vpnProvider != providers.Airvpn &&
		vpnProvider != providers.VPNSecure

	if isUserRequired && *o.User == "" {
		return fmt.Errorf("%w", ErrOpenVPNUserIsEmpty)
	}

	passwordRequired := isUserRequired &&
		(vpnProvider != providers.Ivpn || !ivpnAccountID.MatchString(*o.User))

	if passwordRequired && *o.Password == "" {
		return fmt.Errorf("%w", ErrOpenVPNPasswordIsEmpty)
	}

	err = validateOpenVPNConfigFilepath(isCustom, *o.ConfFile)
	if err != nil {
		return fmt.Errorf("custom configuration file: %w", err)
	}

	err = validateOpenVPNClientCertificate(vpnProvider, *o.Cert)
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}

	err = validateOpenVPNClientKey(vpnProvider, *o.Key)
	if err != nil {
		return fmt.Errorf("client key: %w", err)
	}

	err = validateOpenVPNEncryptedKey(vpnProvider, *o.EncryptedKey)
	if err != nil {
		return fmt.Errorf("encrypted key: %w", err)
	}

	if *o.EncryptedKey != "" && *o.KeyPassphrase == "" {
		return fmt.Errorf("%w", ErrOpenVPNKeyPassphraseIsEmpty)
	}

	const maxMSSFix = 10000
	if *o.MSSFix > maxMSSFix {
		return fmt.Errorf("%w: %d is over the maximum value of %d",
			ErrOpenVPNMSSFixIsTooHigh, *o.MSSFix, maxMSSFix)
	}

	if !regexpInterfaceName.MatchString(o.Interface) {
		return fmt.Errorf("%w: '%s' does not match regex '%s'",
			ErrOpenVPNInterfaceNotValid, o.Interface, regexpInterfaceName)
	}

	if *o.Verbosity < 0 || *o.Verbosity > 6 {
		return fmt.Errorf("%w: %d can only be between 0 and 5",
			ErrOpenVPNVerbosityIsOutOfBounds, o.Verbosity)
	}

	return nil
}

func validateOpenVPNConfigFilepath(isCustom bool,
	confFile string) (err error) {
	if !isCustom {
		return nil
	}

	if confFile == "" {
		return fmt.Errorf("%w", ErrFilepathMissing)
	}

	err = validate.FileExists(confFile)
	if err != nil {
		return err
	}

	extractor := extract.New()
	_, _, err = extractor.Data(confFile)
	if err != nil {
		return fmt.Errorf("extracting information from custom configuration file: %w", err)
	}

	return nil
}

func validateOpenVPNClientCertificate(vpnProvider,
	clientCert string) (err error) {
	switch vpnProvider {
	case
		providers.Airvpn,
		providers.Cyberghost,
		providers.VPNSecure,
		providers.VPNUnlimited:
		if clientCert == "" {
			return fmt.Errorf("%w", ErrMissingValue)
		}
	}

	if clientCert == "" {
		return nil
	}

	_, err = base64.StdEncoding.DecodeString(clientCert)
	if err != nil {
		return err
	}
	return nil
}

func validateOpenVPNClientKey(vpnProvider, clientKey string) (err error) {
	switch vpnProvider {
	case
		providers.Airvpn,
		providers.Cyberghost,
		providers.VPNUnlimited,
		providers.Wevpn:
		if clientKey == "" {
			return fmt.Errorf("%w", ErrMissingValue)
		}
	}

	if clientKey == "" {
		return nil
	}

	_, err = base64.StdEncoding.DecodeString(clientKey)
	if err != nil {
		return err
	}
	return nil
}

func validateOpenVPNEncryptedKey(vpnProvider,
	encryptedPrivateKey string) (err error) {
	if vpnProvider == providers.VPNSecure && encryptedPrivateKey == "" {
		return fmt.Errorf("%w", ErrMissingValue)
	}

	if encryptedPrivateKey == "" {
		return nil
	}

	_, err = base64.StdEncoding.DecodeString(encryptedPrivateKey)
	if err != nil {
		return err
	}
	return nil
}

func (o *OpenVPN) copy() (copied OpenVPN) {
	return OpenVPN{
		Version:       o.Version,
		User:          gosettings.CopyPointer(o.User),
		Password:      gosettings.CopyPointer(o.Password),
		ConfFile:      gosettings.CopyPointer(o.ConfFile),
		Ciphers:       gosettings.CopySlice(o.Ciphers),
		Auth:          gosettings.CopyPointer(o.Auth),
		Cert:          gosettings.CopyPointer(o.Cert),
		Key:           gosettings.CopyPointer(o.Key),
		EncryptedKey:  gosettings.CopyPointer(o.EncryptedKey),
		KeyPassphrase: gosettings.CopyPointer(o.KeyPassphrase),
		PIAEncPreset:  gosettings.CopyPointer(o.PIAEncPreset),
		MSSFix:        gosettings.CopyPointer(o.MSSFix),
		Interface:     o.Interface,
		ProcessUser:   o.ProcessUser,
		Verbosity:     gosettings.CopyPointer(o.Verbosity),
		Flags:         gosettings.CopySlice(o.Flags),
	}
}

// mergeWith merges the other settings into any
// unset field of the receiver settings object.
func (o *OpenVPN) mergeWith(other OpenVPN) {
	o.Version = gosettings.MergeWithString(o.Version, other.Version)
	o.User = gosettings.MergeWithPointer(o.User, other.User)
	o.Password = gosettings.MergeWithPointer(o.Password, other.Password)
	o.ConfFile = gosettings.MergeWithPointer(o.ConfFile, other.ConfFile)
	o.Ciphers = gosettings.MergeWithSlice(o.Ciphers, other.Ciphers)
	o.Auth = gosettings.MergeWithPointer(o.Auth, other.Auth)
	o.Cert = gosettings.MergeWithPointer(o.Cert, other.Cert)
	o.Key = gosettings.MergeWithPointer(o.Key, other.Key)
	o.EncryptedKey = gosettings.MergeWithPointer(o.EncryptedKey, other.EncryptedKey)
	o.KeyPassphrase = gosettings.MergeWithPointer(o.KeyPassphrase, other.KeyPassphrase)
	o.PIAEncPreset = gosettings.MergeWithPointer(o.PIAEncPreset, other.PIAEncPreset)
	o.MSSFix = gosettings.MergeWithPointer(o.MSSFix, other.MSSFix)
	o.Interface = gosettings.MergeWithString(o.Interface, other.Interface)
	o.ProcessUser = gosettings.MergeWithString(o.ProcessUser, other.ProcessUser)
	o.Verbosity = gosettings.MergeWithPointer(o.Verbosity, other.Verbosity)
	o.Flags = gosettings.MergeWithSlice(o.Flags, other.Flags)
}

// overrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (o *OpenVPN) overrideWith(other OpenVPN) {
	o.Version = gosettings.OverrideWithString(o.Version, other.Version)
	o.User = gosettings.OverrideWithPointer(o.User, other.User)
	o.Password = gosettings.OverrideWithPointer(o.Password, other.Password)
	o.ConfFile = gosettings.OverrideWithPointer(o.ConfFile, other.ConfFile)
	o.Ciphers = gosettings.OverrideWithSlice(o.Ciphers, other.Ciphers)
	o.Auth = gosettings.OverrideWithPointer(o.Auth, other.Auth)
	o.Cert = gosettings.OverrideWithPointer(o.Cert, other.Cert)
	o.Key = gosettings.OverrideWithPointer(o.Key, other.Key)
	o.EncryptedKey = gosettings.OverrideWithPointer(o.EncryptedKey, other.EncryptedKey)
	o.KeyPassphrase = gosettings.OverrideWithPointer(o.KeyPassphrase, other.KeyPassphrase)
	o.PIAEncPreset = gosettings.OverrideWithPointer(o.PIAEncPreset, other.PIAEncPreset)
	o.MSSFix = gosettings.OverrideWithPointer(o.MSSFix, other.MSSFix)
	o.Interface = gosettings.OverrideWithString(o.Interface, other.Interface)
	o.ProcessUser = gosettings.OverrideWithString(o.ProcessUser, other.ProcessUser)
	o.Verbosity = gosettings.OverrideWithPointer(o.Verbosity, other.Verbosity)
	o.Flags = gosettings.OverrideWithSlice(o.Flags, other.Flags)
}

func (o *OpenVPN) setDefaults(vpnProvider string) {
	o.Version = gosettings.DefaultString(o.Version, openvpn.Openvpn25)
	o.User = gosettings.DefaultPointer(o.User, "")
	if vpnProvider == providers.Mullvad {
		o.Password = gosettings.DefaultPointer(o.Password, "m")
	} else {
		o.Password = gosettings.DefaultPointer(o.Password, "")
	}

	o.ConfFile = gosettings.DefaultPointer(o.ConfFile, "")
	o.Auth = gosettings.DefaultPointer(o.Auth, "")
	o.Cert = gosettings.DefaultPointer(o.Cert, "")
	o.Key = gosettings.DefaultPointer(o.Key, "")
	o.EncryptedKey = gosettings.DefaultPointer(o.EncryptedKey, "")
	o.KeyPassphrase = gosettings.DefaultPointer(o.KeyPassphrase, "")

	var defaultEncPreset string
	if vpnProvider == providers.PrivateInternetAccess {
		defaultEncPreset = presets.Strong
	}
	o.PIAEncPreset = gosettings.DefaultPointer(o.PIAEncPreset, defaultEncPreset)
	o.MSSFix = gosettings.DefaultPointer(o.MSSFix, 0)
	o.Interface = gosettings.DefaultString(o.Interface, "tun0")
	o.ProcessUser = gosettings.DefaultString(o.ProcessUser, "root")
	o.Verbosity = gosettings.DefaultPointer(o.Verbosity, 1)
}

func (o OpenVPN) String() string {
	return o.toLinesNode().String()
}

func (o OpenVPN) toLinesNode() (node *gotree.Node) {
	node = gotree.New("OpenVPN settings:")
	node.Appendf("OpenVPN version: %s", o.Version)
	node.Appendf("User: %s", gosettings.ObfuscateKey(*o.User))
	node.Appendf("Password: %s", gosettings.ObfuscateKey(*o.Password))

	if *o.ConfFile != "" {
		node.Appendf("Custom configuration file: %s", *o.ConfFile)
	}

	if len(o.Ciphers) > 0 {
		node.Appendf("Ciphers: %s", o.Ciphers)
	}

	if *o.Auth != "" {
		node.Appendf("Auth: %s", *o.Auth)
	}

	if *o.Cert != "" {
		node.Appendf("Client crt: %s", gosettings.ObfuscateKey(*o.Cert))
	}

	if *o.Key != "" {
		node.Appendf("Client key: %s", gosettings.ObfuscateKey(*o.Key))
	}

	if *o.EncryptedKey != "" {
		node.Appendf("Encrypted key: %s (key passhrapse %s)",
			gosettings.ObfuscateKey(*o.EncryptedKey), gosettings.ObfuscateKey(*o.KeyPassphrase))
	}

	if *o.PIAEncPreset != "" {
		node.Appendf("Private Internet Access encryption preset: %s", *o.PIAEncPreset)
	}

	if *o.MSSFix > 0 {
		node.Appendf("MSS Fix: %d", *o.MSSFix)
	}

	if o.Interface != "" {
		node.Appendf("Network interface: %s", o.Interface)
	}

	node.Appendf("Run OpenVPN as: %s", o.ProcessUser)

	node.Appendf("Verbosity level: %d", *o.Verbosity)

	if len(o.Flags) > 0 {
		node.Appendf("Flags: %s", o.Flags)
	}

	return node
}

// WithDefaults is a shorthand using setDefaults.
// It's used in unit tests in other packages.
func (o OpenVPN) WithDefaults(provider string) OpenVPN {
	o.setDefaults(provider)
	return o
}
