import crypto from "node:crypto";
import EventEmitter from "node:events";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import fastifyCors from "@fastify/cors";
import { isNumeric } from "@oirnoir/util";
import { Collection } from "discord.js";
import * as fastify from "fastify";
import mongoose from "mongoose";
import * as ws from "ws";
import ChatCrypto from "./classes/ChatCrypto.js";
import ChatSnowflake from "./classes/ChatSnowflake.js";

import conversationSchema, {
	type IConversation
} from "./schemas/conversation.js";
import inviteCodeSchema, { type IInviteCode } from "./schemas/inviteCode.js";
import messageSchema, { type IMessage } from "./schemas/message.js";
import userSchema, { type IUser } from "./schemas/user.js";

const __dirname = path.dirname(new URL(import.meta.url).pathname);

const frontHostname = "FRONT_HOSTNAME";
const mongodbHostname = "MONGODB_HOSTNAME";

const config = JSON.parse(
	fs.readFileSync(path.join(__dirname, "/config.json"), "utf8")
);

/* cspell: disable-next-line */
const CORS_ALLOWED_HOSTNAMES = [frontHostname];

const banList = new Map<string, number>();

function ban(
	request: fastify.FastifyRequest,
	reply: fastify.FastifyReply,
	until = Date.now() + 86400000
) {
	const ip = getIp(request);
	const banId = ip ?? String(Date.now());
	console.log(`IP-Banned IP ${banId}`);
	banList.set(banId, until);
	return reply;
}

const rateLimits = new Map<keyof typeof RATE_LIMITS, Map<string, number[]>>();
const RATE_LIMITS = {
	VERIFY_INVITE: 5,
	CREATE_ACCOUNT: 2,
	IDENTITY: 100,
	MESSAGE_FETCH: 1200,
	MESSAGE_ACTION: 300
};

for (const action of Object.keys(RATE_LIMITS)) {
	rateLimits.set(action as keyof typeof RATE_LIMITS, new Map());
}

function incrementRatelimit(
	request: fastify.FastifyRequest,
	reply: fastify.FastifyReply,
	action: keyof typeof RATE_LIMITS
) {
	const ip = getIp(request);
	if (ip == null) {
		console.log("IP-less bypass of ratelimit");
		return reply;
	}
	if (rateLimits.get(action)?.get(ip) == null) {
		rateLimits.get(action)?.set(ip, [Date.now() + 300000]);
	} else {
		rateLimits
			.get(action)
			?.get(ip)
			?.push(Date.now() + 300000);
	}
	if (
		(rateLimits
			.get(action)
			?.get(ip)
			?.filter((l) => l > Date.now())?.length ?? 0) > RATE_LIMITS[action]
	) {
		return ban(request, reply, Date.now() + 3600000);
	}
	return reply;
}

function getIp(
	request: fastify.FastifyRequest | http.IncomingMessage
): string | undefined {
	let ipQ = request.headers["cf-connecting-ip"];
	if (Array.isArray(ipQ)) ipQ = ipQ[0] ?? "";
	const ip: string | undefined = ipQ;
	return ip;
}

const httpsConfig =
	process.env.NODE_ENV == "production"
		? null
		: // Null in production because we use nginx
			fs.existsSync(path.join(__dirname, "/certificates/127.0.0.1+2.pem"))
			? {
					key: fs.readFileSync(
						path.join(__dirname, "/certificates/127.0.0.1+2-key.pem"),
						"utf-8"
					),
					cert: fs.readFileSync(
						path.join(__dirname, "/certificates/127.0.0.1+2.pem"),
						"utf-8"
					)
				}
			: null;

const generateRandomString = (length: number) => {
	const chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
	const randomArray = Array.from(
		{ length },
		(_v, _k) => chars[Math.floor(Math.random() * chars.length)]
	);

	const randomString = randomArray.join("");
	return randomString;
};

function generateRandomStringSecure(size: number) {
	return crypto.randomBytes(size).toString("base64url");
}

async function verifyAuthorization(
	server: Server,
	request: fastify.FastifyRequest,
	reply: fastify.FastifyReply
): Promise<
	| { result: false; connection: undefined; user: undefined }
	| { result: true; connection: Connection; user: IUser }
> {
	if (request.headers.authorization == null) {
		reply.status(401).send("Not Logged In");
		return { result: false, connection: undefined, user: undefined };
	}
	const authorizationArgs = request.headers.authorization?.split(" ");
	if (authorizationArgs.length != 2) {
		reply.status(400).send("Bad Request");
		return { result: false, connection: undefined, user: undefined };
	}
	const token = authorizationArgs[1];
	if (token == undefined) {
		reply.status(400).send("Bad Request");
		return { result: false, connection: undefined, user: undefined };
	}
	const tokenHash = await ChatCrypto.hashSHA256String(token);
	const connection = server.wsConnections.find(
		(c) => c.sessionTokenHash == tokenHash
	);
	if (!connection || !connection.authenticated) {
		reply.status(401).send("Bad Authorization 1");
		return { result: false, connection: undefined, user: undefined };
	}
	const user = await server.db.models.User.findOne({
		keys: { Kyber: { publicKey: connection.publicKeyStr } }
	});
	if (!user) {
		reply.status(401).send("Bad Authorization 2");
		return { result: false, connection: undefined, user: undefined };
	}
	return { result: true, connection, user };
}

class Connection {
	socket: ws.WebSocket;
	id: string;
	ip: string;
	sessionTokenHash?: string;
	challengeHash?: string;
	publicKey?: Uint8Array;
	publicKeyStr?: string;
	authenticated: boolean;
	userId?: string;

	constructor(socket: ws.WebSocket, id: string, ip: string) {
		this.socket = socket;
		this.id = id;
		this.ip = ip;
		this.sessionTokenHash = undefined;
		this.challengeHash = undefined;
		this.publicKey = undefined;
		this.publicKeyStr = undefined;
		this.authenticated = false;
		this.userId = undefined;
	}
}

class Server extends EventEmitter {
	db: {
		connection: mongoose.Connection;
		models: {
			Conversation: mongoose.Model<IConversation>;
			InviteCode: mongoose.Model<IInviteCode>;
			Message: mongoose.Model<IMessage>;
			User: mongoose.Model<IUser>;
		};
	};
	wsServer: ws.WebSocketServer;
	httpServer?: http.Server | https.Server;
	fastify: fastify.FastifyInstance;
	port: number;
	wsConnections: Collection<string, Connection>;

	/**
	 * @param {mongoose.Connection} dbConnection
	 */
	constructor(dbConnection: mongoose.Connection) {
		super();

		this.db = {
			connection: dbConnection,
			models: {
				Conversation: dbConnection.model("Conversation", conversationSchema),
				InviteCode: dbConnection.model("InviteCode", inviteCodeSchema),
				Message: dbConnection.model("Message", messageSchema),
				User: dbConnection.model("User", userSchema)
			}
		};

		this.wsServer = new ws.WebSocketServer({
			noServer: true
		});

		this.fastify = fastify.fastify({
			logger: {
				serializers: {
					req(request) {
						return {
							method: request.method,
							url: request.url,
							path: request.routeOptions.url,
							parameters: request.params,
							connectingIp: request.headers["cf-connecting-ip"]
						};
					}
				}
			},
			ignoreTrailingSlash: true,
			serverFactory: (handler, _opts) => {
				const server =
					httpsConfig == null
						? http.createServer((req, res) => {
								handler(req, res);
							})
						: https.createServer(httpsConfig, (req, res) => {
								handler(req, res);
							});

				this.httpServer = server;

				this.httpServer.on("upgrade", (req, socket, head): void => {
					if (req.url != "/gateway") {
						socket.end();
						return;
					}
					const wsServer = this.wsServer;
					this.wsServer.handleUpgrade(req, socket, head, function done(ws) {
						wsServer.emit("connection", ws, req);
					});
				});

				return this.httpServer;
			}
		});

		this.port = process.env.NODE_ENV == "production" ? config.port : 44433;

		this.wsConnections = new Collection();

		this.fastify.register(fastifyCors, {
			origin: CORS_ALLOWED_HOSTNAMES.map((h) => `https://${h}`),
			preflightContinue: true
		});

		this.fastify.addHook("preHandler", (request, reply, done): void => {
			reply
				.header("Content-Security-Policy", "default-src 'self';")
				.header("X-Robots-Tag", "noindex");
			const ip = getIp(request);
			if (
				ip != null &&
				banList.get(ip) != null &&
				(banList.get(ip) ?? 0) > Date.now()
			) {
				reply
					.code(429)
					.send("Your IP has been temporarily blocked. Please try again later.");
				return;
			}
			done();
		});

		// Routes
		this.fastify.options("/login/identity/", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "GET")
				.header("Access-Control-Max-Age", "86400")
				.header("Access-Control-Allow-Headers", "authorization");
		});

		this.fastify.get("/login/identity", async (request, reply) => {
			incrementRatelimit(request, reply, "IDENTITY");

			const {
				result: authResult,
				connection,
				user
			} = await verifyAuthorization(this, request, reply);
			if (!authResult) return;

			connection.userId = user.id;

			await this.db.models.User.updateOne(
				{ id: user.id },
				{ lastConnectionTimestamp: Date.now() }
			);

			return reply.status(200).send({
				userId: user.id,
				usernameEncrypted: user.usernameEncrypted,
				conversations: user.conversations,
				eProfileStore: user.eProfileStore
			});
		});

		// Invites and Accounts

		this.fastify.options("/users", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "POST")
				.header("Access-Control-Max-Age", "86400")
				.header("Access-Control-Allow-Headers", "authorization, content-type");
		});

		this.fastify.post("/users", async (request, reply) => {
			incrementRatelimit(request, reply, "CREATE_ACCOUNT");

			if (
				typeof request.body != "object" ||
				request.headers["content-type"] != "application/json"
			)
				return reply.status(400).send("Bad Request 1");

			// Testing authorization
			if (!request.headers.authorization)
				return reply.status(401).send("Authorization Required");

			if (request.body == null) return reply.status(400).send("Bad Request 2");

			const body: {
				keys?: {
					Kyber?: {
						publicKey?: string;
					};
				};
				usernameEncrypted?: string;
				inviteCode?: string;
			} = request.body;

			// Testing fields
			if (
				!body.keys?.Kyber?.publicKey ||
				!body.usernameEncrypted ||
				!body.inviteCode
			)
				return reply.status(400).send("Bad Request 3");

			// Testing public keys
			try {
				ChatCrypto.importKyberPublicKey(body.keys.Kyber.publicKey);
			} catch {
				return reply.status(400).send("Key Validation Failure");
			}

			const authorizationArgs = request.headers.authorization.split(" ");
			if (authorizationArgs.length != 2)
				return reply.status(400).send("Improper Authorization Format");
			const token = authorizationArgs[1];
			if (token == undefined)
				return reply.status(400).send("Improper Authorization Format");
			const tokenHash = await ChatCrypto.hashSHA256String(token);
			const connection = this.wsConnections.find(
				(c) => c.sessionTokenHash == tokenHash
			);
			if (
				!connection ||
				connection.publicKeyStr != body.keys.Kyber.publicKey ||
				!connection.authenticated
			)
				return reply.status(401).send("Bad Authorization");

			// Check validity of invite code
			const { inviteCode, usernameEncrypted } = body;
			const dbCode = await this.db.models.InviteCode.findOne({
				code: inviteCode
			}).exec();
			if (!dbCode || dbCode.expirationTimestamp <= Date.now())
				return reply.status(400).send("Bad Invite");

			const userId = ChatSnowflake.generate();

			// Create the user
			await this.db.models.User.create({
				id: userId,
				createdTimestamp: Date.now(),
				lastConnectionTimestamp: Date.now(),
				keys: {
					Kyber: {
						publicKey: connection.publicKeyStr
					}
				},
				usernameEncrypted
			});

			// Invalidate invite code for future use
			await this.db.models.InviteCode.deleteOne({ code: dbCode.code });

			console.log(`Account created with ID ${userId}`);

			return reply.status(200).send(userId.toString());
		});

		this.fastify.options("/invites/create", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "POST")
				.header("Access-Control-Max-Age", "86400")
				.header("Access-Control-Allow-Headers", "content-type");
		});

		this.fastify.post("/invites/create", async (request, reply) => {
			console.log(
				`New attempted invite create from IP ${request.headers["cf-connecting-ip"] ?? request.ip}`
			);

			if (
				typeof request.body != "object" ||
				request.headers["content-type"] != "application/json"
			)
				return reply.status(400).send("Bad Request 1");

			if (request.body == null) return reply.status(400).send("Bad Request 2");

			const body: {
				key?: string;
				ts?: number;
			} = request.body;
			// Testing fields
			if (!body.key || !body.ts) return reply.status(400).send("Bad Request 3");

			const inputKeyHash = await ChatCrypto.hashSHA256String(body.key);
			if (inputKeyHash.length != config.accountGenKeyHash.length)
				throw new Error("Hashes are not the same length!");
			if (
				crypto.timingSafeEqual(
					Buffer.from(inputKeyHash, "utf8"),
					Buffer.from(config.accountGenKeyHash, "utf8")
				) === true &&
				body.ts != null
			) {
				const exists = await this.db.models.InviteCode.exists({
					requestedTimestamp: body.ts
				});
				if (exists) return reply.code(400).send("Error");
				const inviteCode = await this.db.models.InviteCode.create({
					code: generateRandomString(16),
					createdTimestamp: Date.now(),
					expirationTimestamp: Date.now() + 604800000,
					requestedTimestamp: body.ts
				});
				console.log(
					`Invite ${inviteCode.code} successfully created by ${request.headers["cf-connecting-ip"] ?? request.ip}`
				);
				return reply
					.code(200)
					.send({ code: inviteCode.code, expiry: inviteCode.expirationTimestamp });
			}
			return ban(request, reply, Date.now() + 86400000)
				.code(401)
				.send("Unauthorized");
		});

		this.fastify.options("/invites/verify/:invite", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "GET")
				.header("Access-Control-Max-Age", "86400");
		});

		this.fastify.get<{ Params: { invite: string } }>(
			"/invites/verify/:invite",
			async (request, reply) => {
				incrementRatelimit(request, reply, "VERIFY_INVITE");
				const exists = await this.db.models.InviteCode.exists({
					code: request.params.invite
				});
				return reply.code(200).send(exists != null);
			}
		);

		// Conversations and Users

		this.fastify.options("/users/:id", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "GET, PATCH")
				.header("Access-Control-Max-Age", "86400")
				.header("Access-Control-Allow-Headers", "authorization, content-type");
		});

		this.fastify.get<{ Params: { id: string } }>(
			"/users/:id",
			async (request, reply) => {
				incrementRatelimit(request, reply, "MESSAGE_FETCH");

				const { result: authResult } = await verifyAuthorization(
					this,
					request,
					reply
				);
				if (!authResult) return;

				const requestedUserId = request.params.id;
				const requestedUser = await this.db.models.User.findOne({
					id: requestedUserId
				});

				if (!requestedUser) return reply.status(404).send("Not Found");

				return reply
					.status(200)
					.send({ publicKey: requestedUser.keys.Kyber.publicKey });
			}
		);

		this.fastify.patch<{
			Params: { id: string };
			Body: {
				conversations: {
					id: string;
					eVerify: string;
					eKeyStore: string;
					eUserIDs: string;
				}[];
				eProfileStore: string;
			};
		}>("/users/:id", async (request, reply) => {
			incrementRatelimit(request, reply, "MESSAGE_FETCH");

			const { result: authResult, user } = await verifyAuthorization(
				this,
				request,
				reply
			);
			if (!authResult) return;

			const requestedUserId = request.params.id;
			if (requestedUserId != "@me" && requestedUserId != user.id)
				return reply.code(403).send("No Access");

			const newConversations = request.body.conversations;
			const newEProfileStore = request.body.eProfileStore;

			const changes: {
				conversations?: IUser["conversations"];
				eProfileStore?: IUser["eProfileStore"];
			} = {};

			if (newConversations != null) {
				if (
					!Array.isArray(newConversations) ||
					!newConversations.every(
						(v) =>
							v.id != null &&
							v.eVerify != null &&
							v.eKeyStore != null &&
							v.eUserIDs != null
					)
				)
					return reply.code(400).send("Invalid type: conversations");
				changes.conversations = newConversations;
			}

			if (newEProfileStore != null) {
				if (typeof newEProfileStore != "string" || newEProfileStore.length <= 0)
					return reply.code(400).send("Invalid type: eProfileStore");
				changes.eProfileStore = newEProfileStore;
			}

			await this.db.models.User.updateOne({ id: user.id }, changes);

			return reply.status(200).send("OK");
		});

		this.fastify.options("/conversations", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "POST")
				.header("Access-Control-Max-Age", "86400")
				.header("Access-Control-Allow-Headers", "authorization, content-type");
		});

		this.fastify.post("/conversations", async (request, reply) => {
			incrementRatelimit(request, reply, "MESSAGE_ACTION");

			const { result: authResult } = await verifyAuthorization(
				this,
				request,
				reply
			);
			if (!authResult) return;

			const verify = generateRandomStringSecure(64);

			const conversation = await this.db.models.Conversation.create({
				id: ChatSnowflake.generate(),
				createdTimestamp: Date.now(),
				verify
			});

			return reply.code(200).send({ id: conversation.id, verify });
		});

		// Messages and Transmission

		this.fastify.options("/messages", async (_request, reply) => {
			reply
				.header("Access-Control-Allow-Methods", "GET, POST")
				.header("Access-Control-Max-Age", "86400")
				.header(
					"Access-Control-Allow-Headers",
					"authorization, content-type, x-conversation-verify"
				);
		});

		this.fastify.get<{
			Querystring: {
				limit: string;
				type: string;
				before: string;
				min_timestamp: string;
				conversation: string;
			};
		}>("/messages", async (request, reply) => {
			incrementRatelimit(request, reply, "MESSAGE_FETCH");

			const { result: authResult, user } = await verifyAuthorization(
				this,
				request,
				reply
			);
			if (!authResult) return;

			// Documentation for this endpoint:
			// Query string:
			// conversation: Used to input the conversation ID to search. Null if type is set to conversationInvitation
			// limit: 1-50, default 50
			// type: A message type to filter
			// before: Used for pagination, the id of the last message fetched
			// min_timestamp: Fetch by minimum timestamp

			let limit = 50;
			if (request.query.limit) {
				limit = Number(request.query.limit);
				if (limit < 1 || limit > 50)
					return await reply.code(400).send("Bad Request: Limit Out of Range");
			}

			let messages = [];

			if (
				request.query.type?.toLowerCase() == "conversationInvitation".toLowerCase()
			) {
				if (
					request.query.before != null &&
					isNumeric(request.query.before, {
						allowNegative: false,
						allowDecimal: false
					})
				) {
					messages = await this.db.models.Message.find({
						recipientId: user.id,
						id: { $lt: BigInt(request.query.before) },
						type: "conversationInvitation"
					})
						.sort({ createdTimestamp: -1 })
						.limit(limit)
						.exec();
				} else if (
					request.query.min_timestamp != null &&
					isNumeric(request.query.min_timestamp, {
						allowNegative: false,
						allowDecimal: false
					})
				) {
					messages = await this.db.models.Message.find({
						recipientId: user.id,
						createdTimestamp: { $gt: Number(request.query.min_timestamp) },
						type: "conversationInvitation"
					})
						.sort({ createdTimestamp: -1 })
						.limit(limit)
						.exec();
				} else {
					messages = await this.db.models.Message.find({
						recipientId: user.id,
						type: "conversationInvitation"
					})
						.sort({ createdTimestamp: -1 })
						.limit(limit)
						.exec();
				}
			} else {
				const conversationId = request.query.conversation;
				const conversationVerify = request.headers["x-conversation-verify"];
				const conversation = await this.db.models.Conversation.findOne({
					id: conversationId
				});
				if (!conversation) return reply.status(404).send("Conversation Not Found");
				if (conversation.verify != conversationVerify)
					return reply.status(403).send("Conversation Verification Invalid");
				if (
					request.query.before != null &&
					isNumeric(request.query.before, {
						allowNegative: false,
						allowDecimal: false
					})
				) {
					if (request.query.type != null) {
						messages = await this.db.models.Message.find({
							conversationId,
							id: { $lt: BigInt(request.query.before) },
							type: request.query.type
						})
							.collation({ locale: "en", strength: 2 })
							.sort({ createdTimestamp: -1 })
							.limit(limit)
							.exec();
					} else {
						messages = await this.db.models.Message.find({
							conversationId,
							id: { $lt: BigInt(request.query.before) }
						})
							.sort({ createdTimestamp: -1 })
							.limit(limit)
							.exec();
					}
				} else if (
					request.query.min_timestamp != null &&
					isNumeric(request.query.min_timestamp, {
						allowDecimal: false,
						allowNegative: false
					})
				) {
					if (request.query.type != null) {
						messages = await this.db.models.Message.find({
							conversationId,
							createdTimestamp: { $gt: Number(request.query.min_timestamp) },
							type: request.query.type
						})
							.collation({ locale: "en", strength: 2 })
							.sort({ createdTimestamp: -1 })
							.limit(limit)
							.exec();
					} else {
						messages = await this.db.models.Message.find({
							conversationId,
							createdTimestamp: { $gt: Number(request.query.min_timestamp) }
						})
							.sort({ createdTimestamp: -1 })
							.limit(limit)
							.exec();
					}
				} else {
					if (request.query.type != null) {
						messages = await this.db.models.Message.find({
							conversationId,
							type: request.query.type
						})
							.collation({ locale: "en", strength: 2 })
							.sort({ createdTimestamp: -1 })
							.limit(limit)
							.exec();
					} else {
						messages = await this.db.models.Message.find({ conversationId })
							.sort({ createdTimestamp: -1 })
							.limit(limit)
							.exec();
					}
				}
			}

			return reply
				.status(200)
				.header("content-type", "application/json")
				.send(
					JSON.stringify(messages, (_, v) =>
						typeof v === "bigint" ? v.toString() : v
					)
				);
		});

		this.fastify.post<{
			Body: {
				recipientId: string;
				nonce: string;
				type: string;
				conversationId: string;
				eContent: string;
			};
		}>("/messages", async (request, reply) => {
			incrementRatelimit(request, reply, "MESSAGE_ACTION");

			const { result: authResult, user } = await verifyAuthorization(
				this,
				request,
				reply
			);
			if (!authResult) return;

			if (!request.body.recipientId)
				return reply.status(400).send("Bad Request 1");
			const recipient = await this.db.models.User.findOne({
				id: request.body.recipientId
			});
			if (!recipient) return reply.status(404).send("Recipient Not Found");

			// Nonce validation
			if (request.body.nonce) {
				const testMessage = await this.db.models.Message.findOne({
					nonce: request.body.nonce
				});
				if (testMessage != null)
					return reply.status(400).send("Message Already Exists");
			}

			// Conversation Verification
			if (request.body.type != "conversationInvitation") {
				const conversationId = request.body.conversationId;
				const conversationVerify = request.headers["x-conversation-verify"];
				const conversation = await this.db.models.Conversation.findOne({
					id: conversationId
				});
				if (!conversation) return reply.status(404).send("Conversation Not Found");
				if (conversation.verify != conversationVerify)
					return reply.status(403).send("Conversation Verification Invalid");
			}

			const message = await this.db.models.Message.create({
				id: ChatSnowflake.generate(),
				createdTimestamp: Date.now(),
				recipientId: recipient.id,
				senderId: user.id,
				conversationId: request.body.conversationId,
				eContent: request.body.eContent,
				nonce: request.body.nonce,
				type: request.body.type
			});

			this.emit("messageCreate", message);

			return reply
				.status(200)
				.header("content-type", "application/json")
				.send(
					JSON.stringify(message, (_, v) =>
						typeof v === "bigint" ? v.toString() : v
					)
				);
		});

		this.fastify.setNotFoundHandler(async (_request, reply) => {
			return void reply
				.status(404)
				.send({ message: "Route not found", error: "Not Found", statusCode: 404 });
		});

		// WS connections

		this.wsServer.on("connection", async (socket, req) => {
			const id = `${Date.now()}${Math.trunc(Math.random() * 100000)}`;
			const ip = getIp(req);
			if (ip == null) return;
			this.wsConnections.set(id, new Connection(socket, id, ip));
			socket.once("close", () => {
				this.wsConnections.delete(id);
			});
			socket.addEventListener("message", async (message) => {
				const connection = this.wsConnections.get(id);
				if (connection == undefined) return;
				const str = message.data.toString();
				let json: { action: string; publicKey?: string; challenge?: string };
				try {
					json = JSON.parse(str);
				} catch {
					console.log("Connection sent invalid json");
					return socket.close(4001, "Invalid JSON");
				}
				switch (json.action) {
					case "authStart": {
						const publicKey = json.publicKey;
						if (!publicKey) return socket.close(4002, "Public key not sent");
						const importedPublicKey = ChatCrypto.importKyberPublicKey(publicKey);
						const { cipherText, symmetricKey } =
							await ChatCrypto.deriveCipherKyber(importedPublicKey);
						const challenge = generateRandomStringSecure(64);
						const challengeHash = await ChatCrypto.hashSHA256String(challenge);
						const challengeEncrypted = await ChatCrypto.encryptAESString(
							symmetricKey,
							challenge
						);
						connection.challengeHash = challengeHash;
						connection.publicKey = importedPublicKey;
						connection.publicKeyStr =
							ChatCrypto.unprotectedKyberExport(importedPublicKey);
						socket.send(
							JSON.stringify({
								action: "authChallenge",
								cipherText,
								challengeEncrypted
							})
						);
						break;
					}
					case "authSolve": {
						const solvedChallenge = json.challenge;
						if (!solvedChallenge) return socket.close(4003, "Challenge not sent");
						const solvedHash = await ChatCrypto.hashSHA256String(solvedChallenge);
						if (solvedHash != connection.challengeHash)
							return socket.close(4004, "Authentication Failure");
						// Success! Authenticated.
						const sessionToken = generateRandomStringSecure(128);
						connection.sessionTokenHash =
							await ChatCrypto.hashSHA256String(sessionToken);
						connection.authenticated = true;
						socket.send(JSON.stringify({ action: "authComplete", sessionToken }));
						break;
					}
					case "identify": {
						const user = await server.db.models.User.findOne({
							keys: { Kyber: { publicKey: connection.publicKeyStr } }
						});
						if (user) {
							connection.userId = user.id;
							await this.db.models.User.updateOne(
								{ id: user.id },
								{ lastConnectionTimestamp: Date.now() }
							);
						}
						break;
					}
				}
			});
		});

		this.on("messageCreate", async (message: IMessage) => {
			const connections = this.wsConnections.filter(
				(c) => c.userId == message.recipientId
			);
			// TODO: Verify that the connection is subscribed to this conversation
			for (const connection of Array.from(connections.values())) {
				connection.socket.send(
					JSON.stringify({ action: "messageCreate", message }, (_, v) =>
						typeof v === "bigint" ? v.toString() : v
					)
				);
			}
		});
	}

	/**
	 * Start the server
	 */
	async start(): Promise<void> {
		await Server._cleanup(this);
		// Debug: Uncomment the following lines to delete conversations, messages, and some user data on startup
		// await this.db.models.Conversation.deleteMany({});
		// await this.db.models.Message.deleteMany({});
		// await this.db.models.User.updateMany({}, { conversations: [], eProfileStore: null });
		console.log("Attempting to start the server...");
		this.fastify.ready(() => {
			if (this.httpServer == undefined) {
				throw new Error("Fastify started without a server!");
			}
			this.httpServer.listen(this.port);
			console.log(`Listening on port ${this.port}`);
		});
		setInterval(async () => {
			await Server._cleanup(this);
		}, 3600000);
	}

	/**
	 * Run a number of cleanup methods
	 */
	static async _cleanup(server: Server): Promise<void> {
		console.log("Running Cleanup");
		// Delete expired invites
		await server.db.models.InviteCode.deleteMany({
			expirationTimestamp: { $lte: Date.now() }
		});
	}
}

const connection = await mongoose.createConnection(mongodbHostname).asPromise();
const server = new Server(connection);
server.start();

async function logUncaughtException(err: unknown) {
	// If you don't want this to crash on a server error,
	// replace this with your own logging function.
	throw err;
}

process.on("uncaughtException", async (err) => {
	logUncaughtException(err);
});

process.on("unhandledRejection", async (err) => {
	logUncaughtException(err);
});

process.on("message", async (message) => {
	if (message == "shutdown") {
		console.log("Shutdown");
		server.wsServer.close();
		server.fastify.close();
		server.httpServer?.close();
		return process.exit(0);
	}
});
