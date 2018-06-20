package n2tok

import (
	"time"
		jwt_lib "github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type TokeCfgFile struct {
	Cfg TokenCfg `yaml:"token"`
}

type TokenCfg struct {
	EncKey   string `yaml:"encKey"`
	ExpHours int    `yaml:"expHours"`
}

// tok defines a token generator object
type tok struct {
	encKey []byte
	exp    int
}

// GetToken generated a HS256 token from an object
func (t *tok) GetToken(v interface{}) (string, error) {
	// make a token
	token := jwt_lib.New(jwt_lib.GetSigningMethod("HS256"))
	token.Claims = jwt_lib.MapClaims{
		"data": v,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}
	tokenString, err := token.SignedString(t.encKey)

	return tokenString, err
}

// NewTokFromYaml returns a configured tok used
func NewTokFromYaml(path string) (*tok, error) {
	ymlData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tokCfgFile := TokeCfgFile{}

	err = yaml.Unmarshal([]byte(ymlData), &tokCfgFile)
	if err != nil {
		return nil, err
	}

	tcfg := tokCfgFile.Cfg

	tok := &tok{encKey: []byte(tcfg.EncKey), exp: tcfg.ExpHours}

	return tok, nil
}
