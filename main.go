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

// googleOAuthConfig is now configured with credentials read from environment variables.
var googleOAuthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8080/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),     // Set your Google Client ID in the environment variable "GOOGLE_CLIENT_ID"
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"), // Set your Google Client Secret in the environment variable "GOOGLE_CLIENT_SECRET"
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
	Endpoint: google.Endpoint,
}

// generateStateToken creates a random string for protecting the OAuth flow from CSRF.
func generateStateToken() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Error generating random state: %v", err)
		return "stateTokenFallback"
	}
	return base64.URLEncoding.EncodeToString(b)
}

// homePage serves a simple homepage with a "Sign in with Google" button.
func homePage(w http.ResponseWriter, r *http.Request) {
	tpl, err := template.ParseFiles("templates/home.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.Execute(w, nil)
}

// handleGoogleLogin initiates the Google OAuth flow by redirecting the user.
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate a new random state token for every auth request
	state := generateStateToken()
	// Store the state token in a cookie (or your session store) for later validation.
	http.SetCookie(w, &http.Cookie{
		Name:  "oauthstate",
		Value: state,
		Path:  "/",
	})
	// Redirect to Google's consent page.
	url := googleOAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleGoogleCallback handles the callback from Google after authentication.
func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Retrieve state value from our cookie.
	cookie, err := r.Cookie("oauthstate")
	if err != nil {
		http.Error(w, "State cookie missing", http.StatusBadRequest)
		return
	}

	// Compare the state value to protect against CSRF.
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

	// Exchange the authorization code for an access token.
	token, err := googleOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the user's public information using the access token.
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

	// Define a user structure to hold the public information.
	var user struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}

	err = json.Unmarshal(userData, &user)
	if err != nil {
		http.Error(w, "Failed unmarshalling JSON: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Render a simple HTML page to display the user's public information.
	tpl, err := template.ParseFiles("templates/profile.html")
	if err != nil {
		http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.Execute(w, user)
}

// main starts the web server and registers our handlers.
func main() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/auth/google", handleGoogleLogin)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)
	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
