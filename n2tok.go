package n2tok

import (
	"time"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"github.com/gin-gonic/gin"
	"strings"
	"fmt"

	jwt_lib "github.com/dgrijalva/jwt-go"
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


func (t *tok) GinParse(c *gin.Context) (map[string]interface{}, error) {

	claims := make(map[string]interface{}, 0)
	tokStr := ""
	authHeader := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authHeader) > 1 && authHeader[0] == "Bearer" {
		tokStr = authHeader[1]
	}

	if len(tokStr) > 0 {
		token, _ := jwt_lib.Parse(tokStr, func(token *jwt_lib.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt_lib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return t.encKey, nil
		})


		if claims, ok := token.Claims.(jwt_lib.MapClaims); ok && token.Valid {
			return claims, nil
		}

	}

	return claims, nil
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
