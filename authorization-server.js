const fs = require("fs")
const express = require("express")
const url = require("url")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/authorize", (request, response) => {
	const clientId = request.query.client_id;
	const client = clients[clientId];

	// unrecognised client id - unauthorised
	if(!client) {
		return response.status(401).send("Error: client not authorized");
	}

	// unsanctioned scope - no permission
	if( typeof request.query.scope !== "string" || !containsAll(client.scopes, request.query.scope.split(" ")) ) {
		return response.status(401).send("Error: invalid scopes requested");
	}

	// generate request token/id
	const requestId = randomString();
	requests[requestId] = request.query;

	// user login
	response.render("login", { // => assets/authorization-server/login.ejs
		client,
		scope: request.query.scope,
		requestId,
	})
});

app.post("/approve", (request, response) => {
	const { userName, password, requestId } = request.body;

	if(!userName || users[userName] !== password) {
		return response.status(401).send("Error: user not authorized");
	}

	const clientReq = requests[requestId];
	delete requests[requestId];

	if(!clientReq) {
		return response.status(401).send("Error: invalid user request");
	}

	// generate authorisation code
	const code = randomString();
	authorizationCodes[code] = { clientReq, userName };

	//redirect user => callback redirect
	const redirectUri = url.parse(clientReq.redirect_uri);
	redirectUri.query = { //set querystring params in redirect uri
		code,
		state: clientReq.state,
	}

	response.redirect(url.format(redirectUri))
});

app.post("/token", (request, response) => {
	let authCredentials = request.headers.authorization;

	if(!authCredentials) {
		return response.status(401).send("Error: not authorized");
	}

	const { clientId, clientSecret } = decodeAuthCredentials(authCredentials);
	const client = clients[clientId];

	if(!client || client.clientSecret !== clientSecret) {
		return response.status(401).send("Error: client not authorized");
	}

	const code = request.body.code;
	if(!code || !authorizationCodes[code]) {
		return response.status(401).send("Error: invalid code");
	}

	const { clientReq, userName } = authorizationCodes[code];
	delete authorizationCodes[code];

	//create and return signed access token (jwt)
	const token = jwt.sign(
		{
			userName,
			scope: clientReq.scope,
		},
		config.privateKey,
		{
			algorithm: "RS256",
			expiresIn: 300,
			issuer: "http://localhost:" + config.port,
		}
	);

	response.json({
		access_token: token,
		token_type: "Bearer",
		scope: clientReq.scope,
	})
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
