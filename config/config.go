package config

const (
	DefaultTimeOut = 60
)

type TLSConfig struct {
	CACert     string `yaml:"ca"`
	Cert       string `yaml:"certification"`
	PrivateKey string `yaml:"private_key"`
	HostName   string `yaml:"host_name"`
}

type Config struct {
	Addr             string     `yaml:"address"`
	TLS              *TLSConfig `yaml:"tls"`
	TimeOut          uint64     `yaml:"timeout"`
	TEEVerifyKeyPath string     `yaml:"tee_root_cert"`
}
