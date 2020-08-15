const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const fs = require("fs")
const { timeout } = require("./utils")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/user-info", (request, response) => {
	if(!request.headers.authorization) {
		return response.status(401).send("Error: client unauthorized");
	}

	const authToken = request.headers.authorization.slice("bearer ". length);
	let userInfo = null;

	try{
		userInfo = jwt.verify(authToken, config.publicKey, {
			algorithms: ["RS256"],
		});
	}catch(error) {
		return response.status(401).send("Error: client unauthorized")
	}

	if(!userInfo) {
		return response.status(401).send("Error: client unauthorized")
	}

	const user = users[userInfo.userName];
	const userWithRestrictedFields = {};
	const scope = userInfo.scope.split(" ");

	for(let i = 0; i < scope.length; i++) {
		const field = scope[i].slice("permission:".length);
		userWithRestrictedFields[field] = user[field];
	}

	response.json(userWithRestrictedFields);
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
