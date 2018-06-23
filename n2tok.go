package n2tok

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"

	"errors"

	jwt_lib "github.com/dgrijalva/jwt-go"
)

// TokeCfgFile
type TokeCfgFile struct {
	Cfg TokenCfg `yaml:"token"`
}

// TokenCfg
type TokenCfg struct {
	EncKey   string `yaml:"encKey"`
	ExpHours int    `yaml:"expHours"`
}

// Claims
type Claims map[string]interface{}

// Tok
type Tok struct {
	Claims Claims
	Valid  bool
	Err    error
	JwtTok *jwtTok
}

// jwtTok defines a token generator object
type jwtTok struct {
	encKey []byte
	exp    int
}

// GinHandler is a middleware for Gin-gonic
func (t *jwtTok) GinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {

		claims, err := t.GinParse(c)
		tok := &Tok{
			Claims: claims,
			JwtTok: t,
			Valid:  true,
			Err:    err,
		}
		if err != nil {
			tok.Err = err
			tok.Valid = false
		}

		c.Set("Tok", tok)
	}
}

// GinParse parses a gin.Context
func (t *jwtTok) GinParse(c *gin.Context) (map[string]interface{}, error) {

	claims := make(Claims, 0)
	tokStr := ""
	authHeader := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authHeader) > 1 && authHeader[0] == "Bearer" {
		tokStr = authHeader[1]
	}

	if len(tokStr) > 0 {
		token, err := jwt_lib.Parse(tokStr, func(token *jwt_lib.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt_lib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return t.encKey, nil
		})

		if err != nil {
			return claims, err
		}

		if claims, ok := token.Claims.(jwt_lib.MapClaims); ok && token.Valid {
			return claims, nil
		}

	}

	return claims, errors.New("invalid token")
}

// GetToken generated a HS256 token from an object
func (t *jwtTok) GetToken(v interface{}) (string, error) {
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
func NewTokFromYaml(path string) (*jwtTok, error) {
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

	tok := &jwtTok{encKey: []byte(tcfg.EncKey), exp: tcfg.ExpHours}

	return tok, nil
}
