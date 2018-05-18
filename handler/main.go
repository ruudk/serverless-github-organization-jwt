package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/oauth2"
	"os"
	"net/http"
	"context"
	"fmt"
	"github.com/shurcooL/githubv4"
	"strings"
	"github.com/dgrijalva/jwt-go"
	"time"
	"crypto/rsa"
)

var (
	privateKeyPem = strings.Replace(os.Getenv("JWT_PRIVATE_KEY"), "*", "\n", -1)
	publicKeyPem  = strings.Replace(os.Getenv("JWT_PUBLIC_KEY"), "*", "\n", -1)

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

	githubConf = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"read:org"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
)

func init() {
	var err error
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPem))
	if err != nil {
		panic(err)
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPem))
	if err != nil {
		panic(err)
	}
}

func main() {
	lambda.Start(Handler)
}

func Handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch request.Resource {
	case "/authorize":
		return handleAuthorize(request)
	case "/callback":
		return handleCallback(request)
	case "/public.pem":
		return handlePublicKey(request)
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 404,
		Body:       "Page not found",
	}, nil
}

func handleAuthorize(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	organization, ok := request.QueryStringParameters["organization"]
	if !ok {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Requires `organization` parameter.",
		}, nil
	}

	if len(organization) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Length of `organization` is too short.",
		}, nil
	}

	url := githubConf.AuthCodeURL(strings.ToLower(organization), oauth2.AccessTypeOnline)

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusFound,
		Headers: map[string]string{
			"Location": url,
		},
	}, nil
}

func handleCallback(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ctx := context.Background()
	code, ok := request.QueryStringParameters["code"]
	if !ok {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Requires `code` parameter.",
		}, nil
	}
	organization, ok := request.QueryStringParameters["state"]
	if !ok {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Requires `state` parameter.",
		}, nil
	}

	tok, err := githubConf.Exchange(ctx, code)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       fmt.Sprintf("Something went wrong: %v", err),
		}, nil
	}

	src := oauth2.StaticTokenSource(tok)
	httpClient := oauth2.NewClient(context.Background(), src)

	client := githubv4.NewClient(httpClient)
	var query struct {
		Viewer struct {
			Login githubv4.String
			Organization struct {
				Login githubv4.String
			} `graphql:"organization(login: $organization)"`
		}
	}

	var vars = map[string]interface{}{
		"organization": githubv4.String(organization),
	}

	err = client.Query(context.Background(), &query, vars)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       fmt.Sprintf("Something went wrong: %v", err),
		}, nil
	}

	if !strings.EqualFold(organization, string(query.Viewer.Organization.Login)) {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       fmt.Sprintf("You don't belong to the %s organization", organization),
		}, nil
	}

	type MyCustomClaims struct {
		Username     string `json:"username"`
		Organization string `json:"organization"`
		GithubToken  string `json:"github_token"`
		jwt.StandardClaims
	}

	// Create the Claims
	claims := MyCustomClaims{
		strings.ToLower(string(query.Viewer.Login)),
		strings.ToLower(string(query.Viewer.Organization.Login)),
		tok.AccessToken,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * 7 * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	ss, err := token.SignedString(privateKey)
	fmt.Printf("%+v", request)

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "text/html",
		},
		Body: fmt.Sprintf(
			"<html><head><style>"+
				"body { font-family: Arial; font-size: 16px; }"+
				"p { margin: 0 0 20px 0; } "+
				".jwt { padding: 20px; width: 50%%; border: 1px solid; word-wrap: break-word; } "+
				"</style></head><body>"+
				"<h1>Hi %s</h1>"+
				"<p>We confirmed that you are part of organization %s.</p>"+
				"<p>You can now use the JWT token below:</p>"+
				"<p class='jwt'>%s</p>"+
				"<p>You can use the <a href=\"/%s/public.pem\">public key</a> to verify this JWT token</p>" +
				"</body></html>",
			query.Viewer.Login,
			query.Viewer.Organization.Login,
			ss,
			request.RequestContext.Stage,
		),
	}, nil
}

func handlePublicKey(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/x-pem-file",
		},
		Body: publicKeyPem,
	}, nil
}
