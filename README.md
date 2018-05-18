# Confirm that a user belongs to a Github Organization

## Installation

Make sure you have Go installed with `brew install golang`

You need to install Serverless (and NodeJS) with:
```
npm install -g serverless
```

Make sure to install `direnv` with:
```
brew install direnv
```

Run `cp .envrc.dist .envrc` and enter all credentials

Then run `direnv allow` in the current directory.

## RSA keys

Generate a RSA key with `openssl genrsa -out jwt.rsa 2048`
Then run `openssl rsa -in jwt.rsa -pubout > jwt.pub`

## Deployment

Run `make deploy-dev` or `make deploy-prod`

## Obtaining tokens

When the lambda is deployed, you can redirects users to
`https://xxxx.execute-api.eu-west-1.amazonaws.com/dev/authorize?organization=<your org name>`

When the user clicks "Authorize" it will verify that the user belongs to the GitHub organization and create a JWT for it.

The JWT token contains the following claims:
```
username: <github username>
organization: <github organization>
github_token: <github access token>
```

The token expires after a week.

## Refreshing tokens

This is not ready yet.

The plan is that clients can send the `github_token` found inside the JWT claim to this service to swap it for a new JWT token.
