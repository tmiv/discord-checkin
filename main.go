package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rs/cors"
)

const DiscordTokenURI = "https://discord.com/api/oauth2/token"
const DiscordUserInfoURI = "https://discord.com/api/users/@me"

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
	tok_req, err := http.NewRequest(http.MethodPost, DiscordTokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tok_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	tok_req.Header.Add("Accept-Encoding", "application/x-www-form-urlencoded")
	tok_resp, err := http.DefaultClient.Do(tok_req)
	if err != nil {
		log.Printf("Error %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if tok_resp.StatusCode < 200 || tok_resp.StatusCode >= 300 {
		log.Printf("Error Bad Response %d", tok_resp.StatusCode)
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
	w.Header().Add("Token", "Generated Token"+userInfo.Id)
	http.Redirect(w, r, "http://localhost:8090/v1/Copyback", http.StatusSeeOther)
}

func Copyback(w http.ResponseWriter, r *http.Request) {
	log.Printf("CB\n")
	log.Printf("%+v\n", r.Header)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/DiscordLogin", DiscordLogin)
	mux.HandleFunc("/v1/Copyback", Copyback)

	handler := cors.Default().Handler(mux)
	http.ListenAndServe("0.0.0.0:8080", handler)
}
