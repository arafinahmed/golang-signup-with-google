package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// googleOAuthConfig is configured with credentials from environment variables.
var googleOAuthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8080/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),     // Set in the environment
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"), // Set in the environment
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
	Endpoint: google.Endpoint,
}

// githubOAuthConfig is configured for GitHub OAuth using environment variables.
var githubOAuthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8080/auth/github/callback",
	ClientID:     os.Getenv("GITHUB_CLIENT_ID"),     // Set in the environment
	ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"), // Set in the environment
	Scopes:       []string{"user:email"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	},
}

// generateStateToken creates a random string to protect the OAuth flow from CSRF.
func generateStateToken() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Error generating random state: %v", err)
		return "stateTokenFallback"
	}
	return base64.URLEncoding.EncodeToString(b)
}

// homePage loads the home template which offers login with Google or GitHub.
func homePage(w http.ResponseWriter, r *http.Request) {
	tpl, err := template.ParseFiles("templates/home.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.Execute(w, nil)
}

// handleGoogleLogin initiates the Google OAuth flow.
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateStateToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Path:     "/",
		HttpOnly: true, // Recommended for security.
		// Secure:   true, // Enable if using HTTPS.
	})
	url := googleOAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleGoogleCallback processes the Google OAuth callback.
func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("oauthstate")
	if err != nil {
		http.Error(w, "State cookie missing", http.StatusBadRequest)
		return
	}
	state := r.FormValue("state")
	if state != cookie.Value {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}
	token, err := googleOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		http.Error(w, "Failed getting user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	userData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		http.Error(w, "Failed reading response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var user struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}
	if err = json.Unmarshal(userData, &user); err != nil {
		http.Error(w, "Failed unmarshalling JSON: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tpl, err := template.ParseFiles("templates/profile.html")
	if err != nil {
		http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.Execute(w, user)
}

// handleGithubLogin initiates the GitHub OAuth flow.
func handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	state := generateStateToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "githuboauthstate",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true, // Enable if using HTTPS.
	})
	url := githubOAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleGithubCallback handles the GitHub OAuth callback.
func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("githuboauthstate")
	if err != nil {
		http.Error(w, "GitHub OAuth state cookie missing", http.StatusBadRequest)
		return
	}
	state := r.FormValue("state")
	if state != cookie.Value {
		http.Error(w, "Invalid GitHub OAuth state", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}
	token, err := githubOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange GitHub token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Retrieve the user's info from GitHub.
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "token "+token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Failed getting GitHub user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed reading GitHub response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err = json.Unmarshal(body, &ghUser); err != nil {
		http.Error(w, "Failed unmarshalling GitHub JSON: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Map GitHub user info to profile fields expected by the template.
	profileData := struct {
		Picture string
		Name    string
		Email   string
	}{
		Picture: ghUser.AvatarURL,
		Name:    ghUser.Name,
		Email:   ghUser.Email,
	}
	// If the GitHub user's name is not set, fallback to the login value.
	if profileData.Name == "" {
		profileData.Name = ghUser.Login
	}
	tpl, err := template.ParseFiles("templates/profile.html")
	if err != nil {
		http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.Execute(w, profileData)
}

func main() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/auth/google", handleGoogleLogin)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)
	http.HandleFunc("/auth/github", handleGithubLogin)
	http.HandleFunc("/auth/github/callback", handleGithubCallback)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
