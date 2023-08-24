package n2tok

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v4"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"strings"
	"time"
)

type TokeCfgFile struct {
	Cfg TokenCfg `yaml:"token"`
}

type TokenCfg struct {
	EncKey   string `yaml:"encKey"`
	ExpHours int    `yaml:"expHours"`
}

type Claims map[string]interface{}

type Tok struct {
	Claims Claims
	Valid  bool
	Err    error
	JwtTok *JwtTok
}

// JwtTok defines a token generator object
type JwtTok struct {
	encKey []byte
	exp    int
}

// GinHandler is a middleware for Gin-gonic
func (t *JwtTok) GinHandler() gin.HandlerFunc {
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
func (t *JwtTok) GinParse(c *gin.Context) (map[string]interface{}, error) {

	claims := make(Claims, 0)
	tokStr := ""
	authHeader := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authHeader) > 1 && authHeader[0] == "Bearer" {
		tokStr = authHeader[1]
	}

	if len(tokStr) > 0 {
		token, err := jwtlib.Parse(tokStr, func(token *jwtlib.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return t.encKey, nil
		})

		if err != nil {
			return claims, err
		}

		if claims, ok := token.Claims.(jwtlib.MapClaims); ok && token.Valid {
			return claims, nil
		}

	}

	return claims, errors.New("invalid token")
}

// GetToken generated a HS256 token from an object
func (t *JwtTok) GetToken(v interface{}) (string, error) {
	// make a token
	token := jwtlib.New(jwtlib.GetSigningMethod("HS256"))

	time.Local = time.UTC
	token.Claims = jwtlib.MapClaims{
		"data": v,
		"exp":  time.Now().Unix() + (int64(t.exp) * 60 * 60),
	}
	tokenString, err := token.SignedString(t.encKey)

	return tokenString, err
}

// NewTokFromYaml returns a configured tok used
func NewTokFromYaml(path string) (*JwtTok, error) {
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

	tok := &JwtTok{encKey: []byte(tcfg.EncKey), exp: tcfg.ExpHours}

	return tok, nil
}
