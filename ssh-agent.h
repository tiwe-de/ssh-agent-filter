/*
 * ssh-agent.h
 *
 * constants copied from http://api.libssh.org/rfc/PROTOCOL.agent
 *
 * public domain.
 */

// 3. Protocol message numbers

// 3.1 Requests from client to agent for protocol 1 key operations

#define SSH_AGENTC_REQUEST_RSA_IDENTITIES		1
#define SSH_AGENTC_RSA_CHALLENGE			3
#define SSH_AGENTC_ADD_RSA_IDENTITY			7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY			8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES		9
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED		24

// 3.2 Requests from client to agent for protocol 2 key operations

#define SSH2_AGENTC_REQUEST_IDENTITIES			11
#define SSH2_AGENTC_SIGN_REQUEST			13
#define SSH2_AGENTC_ADD_IDENTITY			17
#define SSH2_AGENTC_REMOVE_IDENTITY			18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES		19
#define SSH2_AGENTC_ADD_ID_CONSTRAINED			25

// 3.3 Key-type independent requests from client to agent

#define SSH_AGENTC_ADD_SMARTCARD_KEY			20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY			21
#define SSH_AGENTC_LOCK					22
#define SSH_AGENTC_UNLOCK				23
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED	26

// 3.4 Generic replies from agent to client

#define SSH_AGENT_FAILURE				5
#define SSH_AGENT_SUCCESS				6

// 3.5 Replies from agent to client for protocol 1 key operations

#define SSH_AGENT_RSA_IDENTITIES_ANSWER			2
#define SSH_AGENT_RSA_RESPONSE				4

// 3.6 Replies from agent to client for protocol 2 key operations

#define SSH2_AGENT_IDENTITIES_ANSWER			12
#define SSH2_AGENT_SIGN_RESPONSE			14

// 3.7 Key constraint identifiers

#define SSH_AGENT_CONSTRAIN_LIFETIME			1
#define SSH_AGENT_CONSTRAIN_CONFIRM			2
