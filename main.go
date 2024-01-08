package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/cors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

const DiscordTokenURI = "https://discord.com/api/oauth2/token"
const DiscordUserInfoURI = "https://discord.com/api/users/@me"

var (
	RedirectURI = os.Getenv("REDIRECT_URI")
	IdToken     *oauth2.Token
)

type DiscordTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type DiscordUserInfo struct {
	Id       string `json:"id"`
	UserName string `json:"username"`
	Avatar   string `json:"avatar"`
}

func GetDiscordUserInfo(accessToken string) (*DiscordUserInfo, error) {
	user_req, err := http.NewRequest(http.MethodGet, DiscordUserInfoURI, nil)
	if err != nil {
		return nil, err
	}
	user_req.Header.Add("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(user_req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Bad status code returned from user info query %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	userInfo := DiscordUserInfo{}
	err = json.Unmarshal(data, &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func initIdToken(ctx context.Context, aud string) error {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate default credentials: %w", err)
	}

	ts, err := idtoken.NewTokenSource(ctx, aud, option.WithCredentials(credentials))
	if err != nil {
		return fmt.Errorf("failed to create NewTokenSource: %w", err)
	}

	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("failed to receive token: %w", err)
	}

	IdToken = tok

	return nil
}

func getToken(ctx context.Context) (string, error) {
	conf := &oauth2.Config{}
	if IdToken.Expiry.Before(time.Now()) {
		src := conf.TokenSource(ctx, IdToken)
		newToken, err := src.Token() // this actually goes and renews the tokens
		if err != nil {
			return "", err
		}
		if newToken.AccessToken != IdToken.AccessToken {
			IdToken = newToken
		}
	}
	return IdToken.AccessToken, nil
}

func DiscordLogin(w http.ResponseWriter, r *http.Request) {
	codeArray := r.URL.Query()["code"]
	if len(codeArray) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	code := codeArray[0]
	if len(code) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	d_client_id := os.Getenv("DISCORD_CLIENT_ID")
	if len(d_client_id) <= 0 {
		log.Print("DISCORD_CLIENT_ID not set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	d_client_secret := os.Getenv("DISCORD_CLIENT_SECRET")
	if len(d_client_secret) <= 0 {
		log.Print("DISCORD_CLIENT_SECRET not set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	d_redirect_uri := os.Getenv("DISCORD_REDIRECT_URI")
	if len(d_redirect_uri) <= 0 {
		log.Print("DISCORD_REDIRECT_URI not set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data := url.Values{}
	data.Set("client_id", d_client_id)
	data.Set("client_secret", d_client_secret)
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", d_redirect_uri)
	dis_tok_req, err := http.NewRequest(http.MethodPost, DiscordTokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dis_tok_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	dis_tok_req.Header.Add("Accept-Encoding", "application/x-www-form-urlencoded")
	tok_resp, err := http.DefaultClient.Do(dis_tok_req)
	if err != nil {
		log.Printf("Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if tok_resp.StatusCode < 200 || tok_resp.StatusCode >= 300 {
		log.Printf("Error Bad Response %d\n", tok_resp.StatusCode)
		resp, err := io.ReadAll(tok_resp.Body)
		if err == nil {
			log.Printf("Response %s\n", resp)
		}
		tok_resp.Body.Close()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer tok_resp.Body.Close()
	b, err := io.ReadAll(tok_resp.Body)
	if err != nil {
		log.Printf("Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenResp := DiscordTokenResponse{}
	err = json.Unmarshal(b, &tokenResp)
	if err != nil {
		log.Printf("Parse Token Response Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	userInfo, err := GetDiscordUserInfo(tokenResp.AccessToken)
	if err != nil {
		log.Printf("Get User Info Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gtok, err := getToken(r.Context())
	if err != nil {
		log.Printf("Error generating token %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	niv_tok_map := map[string]string{
		"user_id":   userInfo.Id,
		"avatar":    userInfo.Avatar,
		"user_name": userInfo.UserName,
		"aud":       os.Getenv("NIV_TOKEN_AUDIENCE"),
	}
	niv_tok_data, err := json.Marshal(niv_tok_map)
	if err != nil {
		log.Printf("Error Marshaling niv data %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	niv_tok_req, err := http.NewRequest(http.MethodPost, os.Getenv("NIV_TOKEN_URL"), bytes.NewReader(niv_tok_data))
	if err != nil {
		log.Printf("Error generating niv token req %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	niv_tok_req.Header.Add("Content-Type", "application/json")
	niv_tok_req.Header.Add("authorization", "Bearer "+gtok)
	niv_tok_resp, err := http.DefaultClient.Do(niv_tok_req)
	if err != nil {
		log.Printf("Error generating niv token %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if niv_tok_resp.StatusCode < 200 || niv_tok_resp.StatusCode >= 300 {
		log.Printf("Error generating niv token Bad Status %d\n", niv_tok_resp.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer niv_tok_resp.Body.Close()
	niv_tok, err := io.ReadAll(niv_tok_resp.Body)
	if err != nil {
		log.Printf("Error reading niv token %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("URL: %s?token=%s\n", RedirectURI, string(niv_tok))
	http.Redirect(w, r, RedirectURI+"?token="+string(niv_tok), http.StatusSeeOther)
}

func main() {
	err := initIdToken(context.Background(), os.Getenv("G_TOKEN_AUDIENCE"))
	if err != nil {
		log.Fatalf("Could not generate id token %v\n", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/DiscordLogin", DiscordLogin)

	handler := cors.Default().Handler(mux)
	http.ListenAndServe("0.0.0.0:8080", handler)
}
